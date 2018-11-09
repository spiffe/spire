package bundle

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/proto/api/registration"
)

// NewExperimentalSetCommand creates a new "set" subcommand for "bundle" command.
func NewExperimentalSetCommand() cli.Command {
	return newExperimentalSetCommand(defaultEnv, newClients)
}

func newExperimentalSetCommand(env *env, clientsMaker clientsMaker) cli.Command {
	return adaptCommand(env, clientsMaker, new(experimentalSetCommand))
}

type experimentalSetCommand struct {
	// Path to the bundle on disk (optional). If empty, reads from stdin.
	path string
}

func (c *experimentalSetCommand) name() string {
	return "experimental bundle set"
}

func (c *experimentalSetCommand) synopsis() string {
	return "Creates or updates bundle data"
}

func (c *experimentalSetCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.path, "path", "", "Path to the bundle data")
}

func (c *experimentalSetCommand) run(ctx context.Context, env *env, clients *clients) error {
	jwksBytes, err := loadParamData(env.stdin, c.path)
	if err != nil {
		return fmt.Errorf("unable to load bundle data: %v", err)
	}

	bundle, err := parseBundle(jwksBytes)
	if err != nil {
		return err
	}

	federatedBundle := &registration.FederatedBundle{
		Bundle: bundle,
	}

	// pull the existing bundle to know if this should be a create or a update.
	// at some point it might be nice to have a create-or-update style API.
	_, err = clients.r.FetchFederatedBundle(ctx, &registration.FederatedBundleID{
		Id: bundle.TrustDomainId,
	})

	// assume that an error is because the bundle does not exist
	if err == nil {
		_, err = clients.r.UpdateFederatedBundle(ctx, federatedBundle)
	} else {
		_, err = clients.r.CreateFederatedBundle(ctx, federatedBundle)
	}
	if err != nil {
		return err
	}

	return env.Println("bundle set.")
}
