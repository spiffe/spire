package federation

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

func NewShowCommand() cli.Command {
	return newShowCommand(common_cli.DefaultEnv)
}

func newShowCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(showCommand))
}

type showCommand struct {
	// Trust domain name of the federation relationship to show
	trustDomain string
}

func (c *showCommand) Name() string {
	return "federation show"
}

func (c *showCommand) Synopsis() string {
	return "Shows a dynamic federation relationship"
}

func (c *showCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.trustDomain, "trustDomain", "", "The trust domain name of the federation relationship to show")
}

func (c *showCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if c.trustDomain == "" {
		return errors.New("a trust domain name is required")
	}

	trustDomainClient := serverClient.NewTrustDomainClient()

	fr, err := trustDomainClient.GetFederationRelationship(ctx, &trustdomainv1.GetFederationRelationshipRequest{
		TrustDomain: c.trustDomain,
	})
	if err != nil {
		return fmt.Errorf("error showing federation relationship: %w", err)
	}

	env.Printf("Found a federation relationship with trust domain %s:\n\n", c.trustDomain)
	printFederationRelationship(fr, env.Printf)

	return nil
}
