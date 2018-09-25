package bundle

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
)

const (
	headerFmt = `****************************************
* %s
****************************************
`
)

// NewListCommand creates a new "list" subcommand for "bundle" command.
func NewListCommand() cli.Command {
	return newListCommand(defaultEnv, newClients)
}

func newListCommand(env *env, clientsMaker clientsMaker) cli.Command {
	return adaptCommand(env, clientsMaker, new(listCommand))
}

type listCommand struct {
	// SPIFFE ID of the trust bundle
	id string
}

func (c *listCommand) name() string {
	return "bundle list"
}

func (c *listCommand) synopsis() string {
	return "Lists bundle data"
}

func (c *listCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
}

func (c *listCommand) run(ctx context.Context, env *env, clients *clients) error {
	if c.id != "" {
		id, err := idutil.NormalizeSpiffeID(c.id, idutil.AllowAnyTrustDomain())
		if err != nil {
			return err
		}
		bundle, err := clients.r.FetchFederatedBundle(ctx, &registration.FederatedBundleID{
			Id: id,
		})
		if err != nil {
			return err
		}
		return printCACertsPEM(env.stdout, bundle.CaCerts)
	}

	stream, err := clients.r.ListFederatedBundles(ctx, &common.Empty{})
	if err != nil {
		return err
	}

	for i := 0; ; i++ {
		bundle, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		if i != 0 {
			if err := env.Println(); err != nil {
				return err
			}
		}

		if err := env.Printf(headerFmt, bundle.SpiffeId); err != nil {
			return err
		}
		if err := printCACertsPEM(env.stdout, bundle.CaCerts); err != nil {
			return err
		}
	}
	return nil
}

func printCACertsPEM(out io.Writer, caCerts []byte) error {
	certs, err := x509.ParseCertificates(caCerts)
	if err != nil {
		return fmt.Errorf("unable to parse certificates ASN.1 DER data: %v", err)
	}

	for _, cert := range certs {
		if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}
	return nil
}
