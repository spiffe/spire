package bundle

import (
	"context"
	"flag"
	"io"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/api/registration"
	"github.com/spiffe/spire/proto/common"
)

// NewExperimentalListCommand creates a new "list" subcommand for "bundle" command.
func NewExperimentalListCommand() cli.Command {
	return newExperimentalListCommand(defaultEnv, newClients)
}

func newExperimentalListCommand(env *env, clientsMaker clientsMaker) cli.Command {
	return adaptCommand(env, clientsMaker, new(experimentalListCommand))
}

type experimentalListCommand struct {
	// SPIFFE ID of the trust bundle
	id string
}

func (c *experimentalListCommand) name() string {
	return "experimental bundle list"
}

func (c *experimentalListCommand) synopsis() string {
	return "Lists bundle data"
}

func (c *experimentalListCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
}

func (c *experimentalListCommand) run(ctx context.Context, env *env, clients *clients) error {
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
		return printBundle(env.stdout, bundle.Bundle, false)
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

		if err := printBundle(env.stdout, bundle.Bundle, true); err != nil {
			return err
		}
	}
	return nil
}
