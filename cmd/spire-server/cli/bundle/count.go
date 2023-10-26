package bundle

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"

	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
)

type countCommand struct {
	env     *commoncli.Env
	printer cliprinter.Printer
}

// NewCountCommand creates a new "count" subcommand for "bundle" command.
func NewCountCommand() cli.Command {
	return NewCountCommandWithEnv(commoncli.DefaultEnv)
}

// NewCountCommandWithEnv creates a new "count" subcommand for "bundle" command
// using the environment specified.
func NewCountCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &countCommand{env: env})
}

func (*countCommand) Name() string {
	return "bundle count"
}

func (*countCommand) Synopsis() string {
	return "Count bundles"
}

// Run counts attested bundles
func (c *countCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	bundleClient := serverClient.NewBundleClient()
	countResp, err := bundleClient.CountBundles(ctx, &bundlev1.CountBundlesRequest{})
	if err != nil {
		return err
	}

	return c.printer.PrintProto(countResp)
}

func (c *countCommand) AppendFlags(fs *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintCount)
}

func prettyPrintCount(env *commoncli.Env, results ...any) error {
	countResp, ok := results[0].(*bundlev1.CountBundlesResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	count := int(countResp.Count)
	msg := fmt.Sprintf("%d ", count)
	msg = util.Pluralizer(msg, "bundle", "bundles", count)
	return env.Println(msg)
}
