package bundle

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/proto/spire/common"
)

// NewExperimentalShowCommand creates a new "show" subcommand for "bundle" command.
func NewExperimentalShowCommand() cli.Command {
	return newExperimentalShowCommand(defaultEnv, newClients)
}

func newExperimentalShowCommand(env *env, clientsMaker clientsMaker) cli.Command {
	return adaptCommand(env, clientsMaker, new(experimentalShowCommand))
}

type experimentalShowCommand struct {
}

func (c *experimentalShowCommand) name() string {
	return "experimental bundle show"
}

func (c *experimentalShowCommand) synopsis() string {
	return "Prints server CA bundle to stdout"
}

func (c *experimentalShowCommand) appendFlags(fs *flag.FlagSet) {
}

func (c *experimentalShowCommand) run(ctx context.Context, env *env, clients *clients) error {
	bundle, err := clients.r.FetchBundle(ctx, &common.Empty{})
	if err != nil {
		return err
	}
	return printBundle(env.stdout, bundle.Bundle, false)
}
