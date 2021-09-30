package federation

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

func NewListCommand() cli.Command {
	return newListCommand(common_cli.DefaultEnv)
}

func newListCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(listCommand))
}

type listCommand struct {
}

func (c *listCommand) Name() string {
	return "federation list"
}

func (c *listCommand) Synopsis() string {
	return "Lists all dynamic federation relationships"
}

func (c *listCommand) AppendFlags(fs *flag.FlagSet) {
}

func (c *listCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	trustDomainClient := serverClient.NewTrustDomainClient()

	resp, err := trustDomainClient.ListFederationRelationships(ctx, &trustdomainv1.ListFederationRelationshipsRequest{})
	if err != nil {
		return fmt.Errorf("error listing federation relationship: %w", err)
	}

	msg := fmt.Sprintf("Found %v ", len(resp.FederationRelationships))
	msg = util.Pluralizer(msg, "federation relationship", "federation relationships", len(resp.FederationRelationships))

	env.Println(msg)
	for _, fr := range resp.FederationRelationships {
		env.Println()
		printFederationRelationship(fr, env.Printf)
	}

	return nil
}
