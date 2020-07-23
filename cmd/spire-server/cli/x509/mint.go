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
	"io/ioutil"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/api/registration"
)

type generateKeyFunc func() (crypto.Signer, error)

func NewMintCommand() cli.Command {
	return newMintCommand(common_cli.DefaultEnv, nil)
}

func newMintCommand(env *common_cli.Env, generateKey generateKeyFunc) *mintCommand {
	if generateKey == nil {
		generateKey = func() (crypto.Signer, error) {
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
	}
	return &mintCommand{
		env:         env,
		generateKey: generateKey,
	}
}

type mintCommand struct {
	env         *common_cli.Env
	generateKey generateKeyFunc

	socketPath string
	spiffeID   string
	ttl        time.Duration
	dnsNames   common_cli.StringsFlag
	write      string
}

func (c *mintCommand) Help() string {
	_ = c.parseFlags([]string{"-h"})
	return ""
}

func (c *mintCommand) Synopsis() string {
	return "Mints an X509-SVID"
}

func (c *mintCommand) Run(args []string) int {
	if err := c.parseFlags(args); err != nil {
		return 1
	}
	if err := c.run(); err != nil {
		c.env.ErrPrintf("error: %v\n", err)
		return 1
	}
	return 0
}

func (c *mintCommand) parseFlags(args []string) error {
	fs := flag.NewFlagSet("x509 mint", flag.ContinueOnError)
	fs.SetOutput(c.env.Stderr)
	fs.StringVar(&c.socketPath, "registrationUDSPath", util.DefaultSocketPath, "Registration API UDS path")
	fs.StringVar(&c.spiffeID, "spiffeID", "", "SPIFFE ID of the X509-SVID")
	fs.DurationVar(&c.ttl, "ttl", 0, "TTL of the X509-SVID")
	fs.Var(&c.dnsNames, "dns", "DNS name that will be included in SVID. Can be used more than once.")
	fs.StringVar(&c.write, "write", "", "Directory to write output to instead of stdout")
	return fs.Parse(args)
}

func (c *mintCommand) run() error {
	if c.spiffeID == "" {
		return errors.New("spiffeID must be specified")
	}
	key, err := c.generateKey()
	if err != nil {
		return fmt.Errorf("unable to generate key: %v", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return fmt.Errorf("unable to generate CSR: %v", err)
	}

	client, err := util.NewRegistrationClient(c.env.JoinPath(c.socketPath))
	if err != nil {
		return errors.New("cannot create registration client")
	}

	resp, err := client.MintX509SVID(context.Background(), &registration.MintX509SVIDRequest{
		SpiffeId: c.spiffeID,
		Csr:      csr,
		Ttl:      ttlToSeconds(c.ttl),
		DnsNames: c.dnsNames,
	})
	if err != nil {
		return fmt.Errorf("unable to mint SVID: %v", err)
	}

	switch {
	case len(resp.SvidChain) == 0:
		return errors.New("server response missing SVID chain")
	case len(resp.RootCas) == 0:
		return errors.New("server response missing root CAs")
	}

	if eol, err := getX509SVIDEndOfLife(resp.SvidChain[0]); err != nil {
		c.env.ErrPrintf("Unable to determine X509-SVID lifetime: %v\n", err)
	} else if time.Until(eol) < c.ttl {
		c.env.ErrPrintf("X509-SVID lifetime was capped shorter than specified ttl; expires %q\n", eol.UTC().Format(time.RFC3339))
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	svidPEM := new(bytes.Buffer)
	for _, certDER := range resp.SvidChain {
		_ = pem.Encode(svidPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})
	}

	keyPEM := new(bytes.Buffer)
	_ = pem.Encode(keyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	bundlePEM := new(bytes.Buffer)
	for _, rootCA := range resp.RootCas {
		_ = pem.Encode(bundlePEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCA,
		})
	}

	if c.write == "" {
		if err := c.env.Printf("X509-SVID:\n%s\n", svidPEM.String()); err != nil {
			return err
		}
		if err := c.env.Printf("Private key:\n%s\n", keyPEM.String()); err != nil {
			return err
		}
		if err := c.env.Printf("Root CAs:\n%s\n", bundlePEM.String()); err != nil {
			return err
		}
	} else {
		svidPath := c.env.JoinPath(c.write, "svid.pem")
		keyPath := c.env.JoinPath(c.write, "key.pem")
		bundlePath := c.env.JoinPath(c.write, "bundle.pem")

		if err := ioutil.WriteFile(svidPath, svidPEM.Bytes(), 0644); err != nil { // nolint: gosec // expected permission
			return fmt.Errorf("unable to write SVID: %v", err)
		}
		if err := c.env.Printf("X509-SVID written to %s\n", svidPath); err != nil {
			return err
		}

		if err := ioutil.WriteFile(keyPath, keyPEM.Bytes(), 0600); err != nil {
			return fmt.Errorf("unable to write key: %v", err)
		}
		if err := c.env.Printf("Private key written to %s\n", keyPath); err != nil {
			return err
		}

		if err := ioutil.WriteFile(bundlePath, bundlePEM.Bytes(), 0644); err != nil { // nolint: gosec // expected permission
			return fmt.Errorf("unable to write bundle: %v", err)
		}
		if err := c.env.Printf("Root CAs written to %s\n", bundlePath); err != nil {
			return err
		}
	}

	return nil
}

func getX509SVIDEndOfLife(svidDER []byte) (time.Time, error) {
	svid, err := x509.ParseCertificate(svidDER)
	if err != nil {
		return time.Time{}, err
	}
	return svid.NotAfter, nil
}

// ttlToSeconds returns the number of seconds in a duration, rounded up to
// the nearest second
func ttlToSeconds(ttl time.Duration) int32 {
	return int32((ttl + time.Second - 1) / time.Second)
}
