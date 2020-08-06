package bundle

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/spire/api/registration"
	"github.com/spiffe/spire/proto/spire/common"
)

// NewListCommand creates a new "list" subcommand for "bundle" command.
func NewListCommand() cli.Command {
	return newListCommand(defaultEnv, newClients)
}

func newListCommand(env *env, clientsMaker clientsMaker) cli.Command {
	return adaptCommand(env, clientsMaker, new(listCommand))
}

type listCommand struct {
	id     string // SPIFFE ID of the trust bundle
	format string
}

func (c *listCommand) name() string {
	return "bundle list"
}

func (c *listCommand) synopsis() string {
	return "Lists federated bundle data"
}

func (c *listCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	fs.StringVar(&c.format, "format", formatPEM, fmt.Sprintf("The format to list federated bundles. Either %q or %q.", formatPEM, formatJWKS))
}

func (c *listCommand) run(ctx context.Context, env *env, clients *clients) error {
	if c.id != "" {
		id, err := idutil.NormalizeSpiffeID(c.id, idutil.AllowAnyTrustDomain())
		if err != nil {
			return err
		}
		resp, err := clients.r.FetchFederatedBundle(ctx, &registration.FederatedBundleID{
			Id: id,
		})
		if err != nil {
			return err
		}
		return printCommonBundle(env.stdout, resp.Bundle, c.format, false)
	}

	stream, err := clients.r.ListFederatedBundles(ctx, &common.Empty{})
	if err != nil {
		return err
	}

	for i := 0; ; i++ {
		resp, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		bundle := resp.Bundle
		if bundle == nil {
			return errors.New("response missing bundle")
		}

		if i != 0 {
			if err := env.Println(); err != nil {
				return err
			}
		}

		if err := printCommonBundle(env.stdout, bundle, c.format, true); err != nil {
			return err
		}
	}
	return nil
}
