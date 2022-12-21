package jwt

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"gopkg.in/square/go-jose.v2/jwt"
)

func NewMintCommand() cli.Command {
	return newMintCommand(commoncli.DefaultEnv)
}

func newMintCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &mintCommand{env: env})
}

type mintCommand struct {
	spiffeID string
	ttl      time.Duration
	audience commoncli.StringsFlag
	write    string
	env      *commoncli.Env
	printer  cliprinter.Printer
}

func (c *mintCommand) Name() string {
	return "jwt mint"
}
func (c *mintCommand) Synopsis() string {
	return "Mints a JWT-SVID"
}

func (c *mintCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "SPIFFE ID of the JWT-SVID")
	fs.DurationVar(&c.ttl, "ttl", 0, "TTL of the JWT-SVID")
	fs.Var(&c.audience, "audience", "Audience claim that will be included in the SVID. Can be used more than once.")
	fs.StringVar(&c.write, "write", "", "File to write token to instead of stdout")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintMint)
}

func (c *mintCommand) Run(ctx context.Context, env *commoncli.Env, serverClient util.ServerClient) error {
	if c.spiffeID == "" {
		return errors.New("spiffeID must be specified")
	}
	if len(c.audience) == 0 {
		return errors.New("at least one audience must be specified")
	}
	spiffeID, err := spiffeid.FromString(c.spiffeID)
	if err != nil {
		return err
	}

	client := serverClient.NewSVIDClient()
	resp, err := client.MintJWTSVID(ctx, &svidv1.MintJWTSVIDRequest{Id: &types.SPIFFEID{
		TrustDomain: spiffeID.TrustDomain().String(),
		Path:        spiffeID.Path(),
	},
		Ttl:      ttlToSeconds(c.ttl),
		Audience: c.audience,
	})
	if err != nil {
		return fmt.Errorf("unable to mint SVID: %w", err)
	}
	token := resp.Svid.Token
	if err := c.validateToken(token, env); err != nil {
		return err
	}

	// Print in stdout
	if c.write == "" {
		return c.printer.PrintProto(resp)
	}

	// Save in file
	tokenPath := env.JoinPath(c.write)
	if err := diskutil.WritePrivateFile(tokenPath, []byte(token)); err != nil {
		return fmt.Errorf("unable to write token: %w", err)
	}
	return env.Printf("JWT-SVID written to %s\n", tokenPath)
}

func (c *mintCommand) validateToken(token string, env *commoncli.Env) error {
	if token == "" {
		return errors.New("server response missing token")
	}

	eol, err := getJWTSVIDEndOfLife(token)
	if err != nil {
		env.ErrPrintf("Unable to determine JWT-SVID lifetime: %v\n", err)
		return nil
	}

	if time.Until(eol) < c.ttl {
		env.ErrPrintf("JWT-SVID lifetime was capped shorter than specified ttl; expires %q\n", eol.UTC().Format(time.RFC3339))
	}

	return nil
}
func getJWTSVIDEndOfLife(token string) (time.Time, error) {
	t, err := jwt.ParseSigned(token)
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
func ttlToSeconds(ttl time.Duration) int32 {
	return int32((ttl + time.Second - 1) / time.Second)
}

func prettyPrintMint(env *commoncli.Env, results ...interface{}) error {
	if resp, ok := results[0].(*svidv1.MintJWTSVIDResponse); ok {
		return env.Println(resp.Svid.Token)
	}
	return cliprinter.ErrInternalCustomPrettyFunc
}
