package bundle

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

// NewListCommand creates a new "list" subcommand for "bundle" command.
func NewListCommand() cli.Command {
	return newListCommand(commoncli.DefaultEnv)
}

func newListCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &listCommand{env: env})
}

type listCommand struct {
	env          *commoncli.Env
	id           string // SPIFFE ID of the trust bundle
	bundleFormat string
	printer      cliprinter.Printer
}

func (c *listCommand) Name() string {
	return "bundle list"
}

func (c *listCommand) Synopsis() string {
	return "Lists federated bundle data"
}

func (c *listCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	fs.StringVar(&c.bundleFormat, "format", util.FormatPEM, fmt.Sprintf("The format to list federated bundles (only pretty output format supports this flag). Either %q or %q.", util.FormatPEM, util.FormatSPIFFE))
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintList)
}

func (c *listCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	bundleClient := serverClient.NewBundleClient()
	if c.id != "" {
		resp, err := bundleClient.GetFederatedBundle(ctx, &bundlev1.GetFederatedBundleRequest{
			TrustDomain: c.id,
		})
		if err != nil {
			return err
		}
		return c.printer.PrintProto(resp)
	}

	resp, err := bundleClient.ListFederatedBundles(ctx, &bundlev1.ListFederatedBundlesRequest{})
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

func (c *listCommand) prettyPrintList(env *commoncli.Env, results ...interface{}) error {
	if listResp, ok := results[0].(*bundlev1.ListFederatedBundlesResponse); ok {
		for i, bundle := range listResp.Bundles {
			if i != 0 {
				if err := env.Println(); err != nil {
					return err
				}
			}

			if err := printBundleWithFormat(env.Stdout, bundle, c.bundleFormat, true); err != nil {
				return err
			}
		}
		return nil
	}
	if resp, ok := results[0].(*types.Bundle); ok {
		return printBundleWithFormat(env.Stdout, resp, c.bundleFormat, false)
	}

	return cliprinter.ErrInternalCustomPrettyFunc
}
