package bundle

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
)

// NewListCommand creates a new "list" subcommand for "bundle" command.
func NewListCommand() cli.Command {
	return newListCommand(common_cli.DefaultEnv)
}

func newListCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(listCommand))
}

type listCommand struct {
	id     string // SPIFFE ID of the trust bundle
	format string
}

func (c *listCommand) Name() string {
	return "bundle list"
}

func (c *listCommand) Synopsis() string {
	return "Lists federated bundle data"
}

func (c *listCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	fs.StringVar(&c.format, "format", util.FormatPEM, fmt.Sprintf("The format to list federated bundles. Either %q or %q.", util.FormatPEM, util.FormatSPIFFE))
}

func (c *listCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	bundleClient := serverClient.NewBundleClient()
	if c.id != "" {
		id, err := idutil.NormalizeSpiffeID(c.id, idutil.AllowAnyTrustDomain())
		if err != nil {
			return err
		}
		resp, err := bundleClient.GetFederatedBundle(ctx, &bundlev1.GetFederatedBundleRequest{
			TrustDomain: id,
		})
		if err != nil {
			return err
		}
		return printBundleWithFormat(env.Stdout, resp, c.format, false)
	}

	resp, err := bundleClient.ListFederatedBundles(ctx, &bundlev1.ListFederatedBundlesRequest{})
	if err != nil {
		return err
	}

	for i, b := range resp.Bundles {
		if i != 0 {
			if err := env.Println(); err != nil {
				return err
			}
		}

		if err := printBundleWithFormat(env.Stdout, b, c.format, true); err != nil {
			return err
		}
	}
	return nil
}
