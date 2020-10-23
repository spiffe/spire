package bundle

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

// NewExperimentalListCommand creates a new "list" subcommand for "bundle" command.
func NewExperimentalListCommand() cli.Command {
	return newExperimentalListCommand(common_cli.DefaultEnv)
}

func newExperimentalListCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(experimentalListCommand))
}

type experimentalListCommand struct {
	// SPIFFE ID of the trust bundle
	id string
}

func (c *experimentalListCommand) Name() string {
	return `experimental bundle list (deprecated - please use "bundle list" instead)`
}

func (c *experimentalListCommand) Synopsis() string {
	return `Lists bundle data. This command has been deprecated and will be removed in a future release. Its functionality was subsumed into the "bundle list" command.`
}

func (c *experimentalListCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
}

func (c *experimentalListCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	listCommand := listCommand{
		id:     c.id,
		format: formatSPIFFE,
	}

	return listCommand.Run(ctx, env, serverClient)
}
