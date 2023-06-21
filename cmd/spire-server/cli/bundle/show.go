package bundle

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

// NewShowCommand creates a new "show" subcommand for "bundle" command.
func NewShowCommand() cli.Command {
	return newShowCommand(common_cli.DefaultEnv)
}

func newShowCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, &showCommand{env: env})
}

type showCommand struct {
	env          *common_cli.Env
	bundleFormat string
	printer      cliprinter.Printer
}

func (c *showCommand) Name() string {
	return "bundle show"
}

func (c *showCommand) Synopsis() string {
	return "Prints server CA bundle to stdout"
}

func (c *showCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.bundleFormat, "format", util.FormatPEM, fmt.Sprintf("The format to show the bundle (only pretty output format supports this flag). Either %q or %q.", util.FormatPEM, util.FormatSPIFFE))
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintBundle)
}

func (c *showCommand) Run(ctx context.Context, _ *common_cli.Env, serverClient util.ServerClient) error {
	bundleClient := serverClient.NewBundleClient()
	resp, err := bundleClient.GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

func (c *showCommand) prettyPrintBundle(env *common_cli.Env, results ...interface{}) error {
	showResp, ok := results[0].(*types.Bundle)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	return printBundleWithFormat(env.Stdout, showResp, c.bundleFormat, false)
}
