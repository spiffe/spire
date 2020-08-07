package bundle

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
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
	return `experimental bundle show (deprecated - please use "bundle show" instead)`
}

func (c *experimentalShowCommand) synopsis() string {
	return `Prints server CA bundle to stdout. This command has been deprecated and will be removed in a future release. Its functionality was subsumed into the "bundle show" command.`
}

func (c *experimentalShowCommand) appendFlags(fs *flag.FlagSet) {
}

func (c *experimentalShowCommand) run(ctx context.Context, env *env, clients *clients) error {
	showCommand := showCommand{
		format: formatSPIFFE,
	}

	return showCommand.run(ctx, env, clients)
}
