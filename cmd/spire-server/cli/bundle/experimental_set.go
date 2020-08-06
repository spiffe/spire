package bundle

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
)

// NewExperimentalSetCommand creates a new "set" subcommand for "bundle" command.
func NewExperimentalSetCommand() cli.Command {
	return newExperimentalSetCommand(defaultEnv, newClients)
}

func newExperimentalSetCommand(env *env, clientsMaker clientsMaker) cli.Command {
	return adaptCommand(env, clientsMaker, new(experimentalSetCommand))
}

type experimentalSetCommand struct {
	// The trust domain ID of the bundle being set.
	id string

	// Path to the bundle on disk (optional). If empty, reads from stdin.
	path string
}

func (c *experimentalSetCommand) name() string {
	return `experimental bundle set (deprecated - please use "bundle set" instead)`
}

func (c *experimentalSetCommand) synopsis() string {
	return `Creates or updates bundle data. This command has been deprecated and will be removed in a future release. Its functionality was subsumed into the "bundle set" command.`
}

func (c *experimentalSetCommand) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	fs.StringVar(&c.path, "path", "", "Path to the bundle data")
}

func (c *experimentalSetCommand) run(ctx context.Context, env *env, clients *clients) error {
	setCommand := setCommand{
		id:     c.id,
		path:   c.path,
		format: formatJWKS,
	}

	return setCommand.run(ctx, env, clients)
}
