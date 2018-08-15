package bundle

import (
	"context"
	"errors"
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/proto/api/registration"
)

// NewDeleteCommand creates a new "delete" subcommand for "bundle" command.
func NewDeleteCommand() cli.Command {
	return newDeleteCommand(defaultEnv, newClients)
}

func newDeleteCommand(env *env, clientsMaker clientsMaker) cli.Command {
	return adaptCommand(env, clientsMaker, new(deleteCommand))
}

type deleteCommand struct {
	// SPIFFE ID of the trust domain bundle
	id string
}

func (c *deleteCommand) name() string {
	return "bundle delete"
}

func (c *deleteCommand) synopsis() string {
	return "Deletes bundle data"
}

func (c *deleteCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
}

func (c *deleteCommand) run(ctx context.Context, env *env, clients *clients) error {
	if c.id == "" {
		return errors.New("id is required")
	}

	if err := idutil.ValidateSpiffeID(c.id, idutil.AllowAnyTrustDomain()); err != nil {
		return err
	}

	if _, err := clients.r.DeleteFederatedBundle(ctx, &registration.FederatedBundleID{
		Id: c.id,
	}); err != nil {
		return err
	}

	return env.Println("bundle deleted.")
}
