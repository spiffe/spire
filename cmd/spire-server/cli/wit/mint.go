package wit

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	serverutil "github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
)

func NewMintCommand() cli.Command {
	return newMintCommand(commoncli.DefaultEnv)
}

func newMintCommand(env *commoncli.Env) cli.Command {
	return serverutil.AdaptCommand(env, &mintCommand{env: env})
}

// Test helper function, to have control over the workload key that is being generated
func newMintCommandWithKeyGenerator(env *commoncli.Env, workloadKeyGenerator func() (crypto.Signer, error)) cli.Command {
	return serverutil.AdaptCommand(env, &mintCommand{env: env, workloadKeyGenerator: workloadKeyGenerator})
}

type mintCommand struct {
	spiffeID             string
	keyType              string
	signingAlgorithm     string
	ttl                  time.Duration
	write                string
	env                  *commoncli.Env
	printer              cliprinter.Printer
	workloadKeyGenerator func() (crypto.Signer, error)
}

func (c *mintCommand) Name() string {
	return "wit mint"
}

func (c *mintCommand) Synopsis() string {
	return "Mints a WIT-SVID"
}

func (c *mintCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "SPIFFE ID of the WIT-SVID")
	fs.StringVar(&c.keyType, "keyType", "ec-p256", "Key type of the WIT-SVID")
	fs.StringVar(&c.signingAlgorithm, "signingAlgorithm", "ES256", "Signing algorithm for the workload signing key")
	fs.DurationVar(&c.ttl, "ttl", 0, "TTL of the WIT-SVID")
	fs.StringVar(&c.write, "write", "", "Directory to write output to instead of stdout")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintMint)
}

type mintResult struct {
	PrivateKey string         `json:"private_key"`
	Svid       *types.WITSVID `json:"svid"`
}

func (c *mintCommand) Run(ctx context.Context, env *commoncli.Env, serverClient serverutil.ServerClient) error {
	if c.spiffeID == "" {
		return errors.New("spiffeID must be specified")
	}
	spiffeID, err := spiffeid.FromString(c.spiffeID)
	if err != nil {
		return err
	}
	ttl, err := ttlToSeconds(c.ttl)
	if err != nil {
		return fmt.Errorf("invalid value for TTL: %w", err)
	}

	keyType, err := validateKeyTypeAndSigningAlgorithm(c.keyType, c.signingAlgorithm)
	if err != nil {
		return err
	}

	if c.workloadKeyGenerator == nil {
		c.workloadKeyGenerator = keyType.GenerateSigner
	}

	signer, err := c.workloadKeyGenerator()
	if err != nil {
		return fmt.Errorf("could not generate public/private key pair: %w", err)
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("could not marshal public/private key pair: %w", err)
	}

	client := serverClient.NewSVIDClient()
	resp, err := client.MintWITSVID(ctx, &svidv1.MintWITSVIDRequest{
		Id: &types.SPIFFEID{
			TrustDomain: spiffeID.TrustDomain().Name(),
			Path:        spiffeID.Path(),
		},
		PublicKey:        publicKeyDer,
		SigningAlgorithm: c.signingAlgorithm,
		Ttl:              ttl,
	})
	if err != nil {
		return fmt.Errorf("unable to mint SVID: %w", err)
	}
	token := resp.Svid.Token
	if err := c.validateToken(token, env); err != nil {
		return err
	}

	jwk := jose.JSONWebKey{
		Key: signer,
	}
	jwkJson, err := jwk.MarshalJSON()
	if err != nil {
		return fmt.Errorf("could not marshal private key: %w", err)
	}

	// Print in stdout
	if c.write == "" {
		return c.printer.PrintStruct(&mintResult{
			PrivateKey: string(jwkJson),
			Svid:       resp.Svid,
		})
	}

	tokenPath := env.JoinPath(c.write, "token")
	keyPath := env.JoinPath(c.write, "key")

	if err := diskutil.WritePrivateFile(tokenPath, []byte(token)); err != nil {
		return fmt.Errorf("unable to write token: %w", err)
	}
	if err := env.Printf("WIT-SVID written to %s\n", tokenPath); err != nil {
		return err
	}
	if err := diskutil.WritePrivateFile(keyPath, jwkJson); err != nil {
		return fmt.Errorf("unable to write key: %w", err)
	}
	return env.Printf("Private key written to %s\n", keyPath)
}

func (c *mintCommand) validateToken(token string, env *commoncli.Env) error {
	if token == "" {
		return errors.New("server response missing token")
	}

	eol, err := getWITSVIDEndOfLife(token)
	if err != nil {
		env.ErrPrintf("Unable to determine WIT-SVID lifetime: %v\n", err)
		return nil
	}

	if time.Until(eol) < c.ttl {
		env.ErrPrintf("WIT-SVID lifetime was capped shorter than specified ttl; expires %q\n", eol.UTC().Format(time.RFC3339))
	}

	return nil
}

func getWITSVIDEndOfLife(token string) (time.Time, error) {
	t, err := jwt.ParseSigned(token, jwtsvid.AllowedSignatureAlgorithms)
	if err != nil {
		return time.Time{}, err
	}

	claims := new(jwt.Claims)
	if err := t.UnsafeClaimsWithoutVerification(claims); err != nil {
		return time.Time{}, err
	}

	if claims.Expiry == nil {
		return time.Time{}, errors.New("no expiry claim")
	}

	return claims.Expiry.Time(), nil
}

// ttlToSeconds returns the number of seconds in a duration, rounded up to
// the nearest second
func ttlToSeconds(ttl time.Duration) (int32, error) {
	return util.CheckedCast[int32]((ttl + time.Second - 1) / time.Second)
}

func prettyPrintMint(env *commoncli.Env, results ...any) error {
	resultInterface, ok := results[0].([]any)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	if wit, ok := resultInterface[0].(*mintResult); ok {
		errToken := env.Println(wit.Svid.Token)
		errKey := env.Println(wit.PrivateKey)
		return errors.Join(errToken, errKey)
	}
	return cliprinter.ErrInternalCustomPrettyFunc
}

func validateKeyTypeAndSigningAlgorithm(keyType string, signingAlgorithm string) (keymanager.KeyType, error) {
	switch signingAlgorithm {
	case "RS256":
		fallthrough
	case "RS384":
		fallthrough
	case "RS512":
		fallthrough
	case "PS256":
		fallthrough
	case "PS384":
		fallthrough
	case "PS512":
		switch keyType {
		case "rsa-2048":
			return keymanager.RSA2048, nil
		case "rsa-4096":
			return keymanager.RSA4096, nil
		default:
			return keymanager.KeyTypeUnset, fmt.Errorf("unsupported key type '%s' for signing algorithm '%s'", keyType, signingAlgorithm)
		}
	case "ES256":
		if keyType != "ec-p256" {
			return keymanager.KeyTypeUnset, fmt.Errorf("unsupported key type '%s' for '%s' signing algorithm", keyType, signingAlgorithm)
		}
		return keymanager.ECP256, nil
	case "ES384":
		if keyType != "ec-p384" {
			return keymanager.KeyTypeUnset, fmt.Errorf("unsupported key type '%s' for '%s' signing algorithm", keyType, signingAlgorithm)
		}
		return keymanager.ECP384, nil
	default:
		return keymanager.KeyTypeUnset, fmt.Errorf("unsupported signing algorithm: %s", signingAlgorithm)
	}
}
