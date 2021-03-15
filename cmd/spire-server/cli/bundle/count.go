package bundle

import (
	"flag"
	"fmt"

	"github.com/mitchellh/cli"

	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/api/server/bundle/v1"

	"golang.org/x/net/context"
)

type countCommand struct{}

// NewCountCommand creates a new "count" subcommand for "bundle" command.
func NewCountCommand() cli.Command {
	return NewCountCommandWithEnv(common_cli.DefaultEnv)
}

// NewCountCommandWithEnv creates a new "count" subcommand for "bundle" command
// using the environment specified.
func NewCountCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(countCommand))
}

func (*countCommand) Name() string {
	return "bundle count"
}

func (countCommand) Synopsis() string {
	return "Count bundles"
}

//Run counts attested bundles
func (c *countCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	bundleClient := serverClient.NewBundleClient()
	countResponse, err := bundleClient.CountBundles(ctx, &bundle.CountBundlesRequest{})
	if err != nil {
		return err
	}

	count := int(countResponse.Count)
	msg := fmt.Sprintf("%d ", count)
	msg = util.Pluralizer(msg, "bundle", "bundles", count)
	env.Println(msg)

	return nil
}

func (c *countCommand) AppendFlags(fs *flag.FlagSet) {
}
