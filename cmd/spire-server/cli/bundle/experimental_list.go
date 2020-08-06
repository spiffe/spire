package bundle

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
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
	return `experimental bundle list (deprecated - please use "bundle list" instead)`
}

func (c *experimentalListCommand) synopsis() string {
	return `Lists bundle data. This command has been deprecated and will be removed in a future release. Its functionality was subsumed into the "bundle list" command.`
}

func (c *experimentalListCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
}

func (c *experimentalListCommand) run(ctx context.Context, env *env, clients *clients) error {
	listCommand := listCommand{
		id:     c.id,
		format: formatJWKS,
	}

	return listCommand.run(ctx, env, clients)
}
