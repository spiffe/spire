package x509

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/diskutil"
)

type generateKeyFunc func() (crypto.Signer, error)

func NewMintCommand() cli.Command {
	return newMintCommand(commoncli.DefaultEnv, nil)
}

func newMintCommand(env *commoncli.Env, generateKey generateKeyFunc) cli.Command {
	if generateKey == nil {
		generateKey = func() (crypto.Signer, error) {
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
	}
	return util.AdaptCommand(env, &mintCommand{
		generateKey: generateKey,
		env:         env,
	})
}

type mintCommand struct {
	generateKey generateKeyFunc

	spiffeID string
	ttl      time.Duration
	dnsNames commoncli.StringsFlag
	write    string
	env      *commoncli.Env
	printer  cliprinter.Printer
}

func (c *mintCommand) Name() string {
	return "x509 mint"
}

func (c *mintCommand) Synopsis() string {
	return "Mints an X509-SVID"
}

func (c *mintCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "SPIFFE ID of the X509-SVID")
	fs.DurationVar(&c.ttl, "ttl", 0, "TTL of the X509-SVID")
	fs.Var(&c.dnsNames, "dns", "DNS name that will be included in SVID. Can be used more than once.")
	fs.StringVar(&c.write, "write", "", "Directory to write output to instead of stdout")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintMint)
}

func (c *mintCommand) Run(ctx context.Context, env *commoncli.Env, serverClient util.ServerClient) error {
	if c.spiffeID == "" {
		return errors.New("spiffeID must be specified")
	}

	id, err := spiffeid.FromString(c.spiffeID)
	if err != nil {
		return err
	}

	key, err := c.generateKey()
	if err != nil {
		return fmt.Errorf("unable to generate key: %w", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		URIs:     []*url.URL{id.URL()},
		DNSNames: c.dnsNames,
	}, key)
	if err != nil {
		return fmt.Errorf("unable to generate CSR: %w", err)
	}

	client := serverClient.NewSVIDClient()
	resp, err := client.MintX509SVID(ctx, &svidv1.MintX509SVIDRequest{
		Csr: csr,
		Ttl: ttlToSeconds(c.ttl),
	})
	if err != nil {
		return fmt.Errorf("unable to mint SVID: %w", err)
	}

	if len(resp.Svid.CertChain) == 0 {
		return errors.New("server response missing SVID chain")
	}

	bundleClient := serverClient.NewBundleClient()
	ca, err := bundleClient.GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return fmt.Errorf("unable to get bundle: %w", err)
	}

	if len(ca.X509Authorities) == 0 {
		return errors.New("server response missing X509 Authorities")
	}

	eol := time.Unix(resp.Svid.ExpiresAt, 0)
	if time.Until(eol) < c.ttl {
		env.ErrPrintf("X509-SVID lifetime was capped shorter than specified ttl; expires %q\n", eol.UTC().Format(time.RFC3339))
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	rootCAs := make([][]byte, len(ca.X509Authorities))
	for i, rootCA := range ca.X509Authorities {
		rootCAs[i] = rootCA.Asn1
	}

	if c.write == "" {
		return c.printer.PrintStruct(&mintResult{
			X509SVID:   resp.Svid.CertChain,
			PrivateKey: keyBytes,
			RootCAs:    rootCAs,
		})
	}

	svidPEM, keyPEM, bundlePEM := convertSVIDResultToPEM(keyBytes, resp.Svid.CertChain, rootCAs)

	svidPath := env.JoinPath(c.write, "svid.pem")
	keyPath := env.JoinPath(c.write, "key.pem")
	bundlePath := env.JoinPath(c.write, "bundle.pem")

	if err := diskutil.WritePubliclyReadableFile(svidPath, svidPEM.Bytes()); err != nil {
		return fmt.Errorf("unable to write SVID: %w", err)
	}
	if err := env.Printf("X509-SVID written to %s\n", svidPath); err != nil {
		return err
	}

	if err := diskutil.WritePrivateFile(keyPath, keyPEM.Bytes()); err != nil {
		return fmt.Errorf("unable to write key: %w", err)
	}
	if err := env.Printf("Private key written to %s\n", keyPath); err != nil {
		return err
	}

	if err := diskutil.WritePubliclyReadableFile(bundlePath, bundlePEM.Bytes()); err != nil {
		return fmt.Errorf("unable to write bundle: %w", err)
	}
	return env.Printf("Root CAs written to %s\n", bundlePath)
}

// ttlToSeconds returns the number of seconds in a duration, rounded up to
// the nearest second
func ttlToSeconds(ttl time.Duration) int32 {
	return int32((ttl + time.Second - 1) / time.Second)
}

type mintResult struct {
	X509SVID   [][]byte `json:"x509_svid"`
	PrivateKey []byte   `json:"private_key"`
	RootCAs    [][]byte `json:"root_cas"`
}

func (c *mintCommand) prettyPrintMint(env *commoncli.Env, results ...any) error {
	if resultInterface, ok := results[0].([]any); ok {
		result, ok := resultInterface[0].(*mintResult)
		if !ok {
			return errors.New("unexpected type")
		}

		svidPEM, keyPEM, bundlePEM := convertSVIDResultToPEM(result.PrivateKey, result.X509SVID, result.RootCAs)

		if err := env.Printf("X509-SVID:\n%s\n", svidPEM.String()); err != nil {
			return err
		}
		if err := env.Printf("Private key:\n%s\n", keyPEM.String()); err != nil {
			return err
		}
		return env.Printf("Root CAs:\n%s\n", bundlePEM.String())
	}

	return cliprinter.ErrInternalCustomPrettyFunc
}

func convertSVIDResultToPEM(privateKey []byte, svidCertChain, rootCAs [][]byte) (*bytes.Buffer, *bytes.Buffer, *bytes.Buffer) {
	svidPEM := new(bytes.Buffer)
	for _, certDER := range svidCertChain {
		_ = pem.Encode(svidPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})
	}

	keyPEM := new(bytes.Buffer)
	_ = pem.Encode(keyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKey,
	})

	bundlePEM := new(bytes.Buffer)
	for _, rootCA := range rootCAs {
		_ = pem.Encode(bundlePEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCA,
		})
	}
	return svidPEM, keyPEM, bundlePEM
}
