package bundle

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

// NewShowCommand creates a new "show" subcommand for "bundle" command.
func NewShowCommand() cli.Command {
	return newShowCommand(common_cli.DefaultEnv)
}

func newShowCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(showCommand))
}

type showCommand struct {
	format string
}

func (c *showCommand) Name() string {
	return "bundle show"
}

func (c *showCommand) Synopsis() string {
	return "Prints server CA bundle to stdout"
}

func (c *showCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.format, "format", util.FormatPEM, fmt.Sprintf("The format to show the bundle. Either %q or %q.", util.FormatPEM, util.FormatSPIFFE))
}

func (c *showCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	bundleClient := serverClient.NewBundleClient()
	resp, err := bundleClient.GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return err
	}

	return printBundleWithFormat(env.Stdout, resp, c.format, false)
}
