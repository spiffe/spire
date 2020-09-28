package bundle

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

// NewExperimentalSetCommand creates a new "set" subcommand for "bundle" command.
func NewExperimentalSetCommand() cli.Command {
	return newExperimentalSetCommand(common_cli.DefaultEnv)
}

func newExperimentalSetCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(experimentalSetCommand))
}

type experimentalSetCommand struct {
	// The trust domain ID of the bundle being set.
	id string

	// Path to the bundle on disk (optional). If empty, reads from stdin.
	path string
}

func (c *experimentalSetCommand) Name() string {
	return `experimental bundle set (deprecated - please use "bundle set" instead)`
}

func (c *experimentalSetCommand) Synopsis() string {
	return `Creates or updates bundle data. This command has been deprecated and will be removed in a future release. Its functionality was subsumed into the "bundle set" command.`
}

func (c *experimentalSetCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	fs.StringVar(&c.path, "path", "", "Path to the bundle data")
}

func (c *experimentalSetCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	setCommand := setCommand{
		id:     c.id,
		path:   c.path,
		format: formatSPIFFE,
	}

	return setCommand.Run(ctx, env, serverClient)
}
