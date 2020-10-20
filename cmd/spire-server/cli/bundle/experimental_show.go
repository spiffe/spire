package bundle

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

// NewExperimentalShowCommand creates a new "show" subcommand for "bundle" command.
func NewExperimentalShowCommand() cli.Command {
	return newExperimentalShowCommand(common_cli.DefaultEnv)
}

func newExperimentalShowCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(experimentalShowCommand))
}

type experimentalShowCommand struct {
}

func (c *experimentalShowCommand) Name() string {
	return `experimental bundle show (deprecated - please use "bundle show" instead)`
}

func (c *experimentalShowCommand) Synopsis() string {
	return `Prints server CA bundle to stdout. This command has been deprecated and will be removed in a future release. Its functionality was subsumed into the "bundle show" command.`
}

func (c *experimentalShowCommand) AppendFlags(fs *flag.FlagSet) {
}

func (c *experimentalShowCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	showCommand := showCommand{
		format: formatSPIFFE,
	}

	return showCommand.Run(ctx, env, serverClient)
}
