package federation

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/idutil"
	"google.golang.org/grpc/codes"
)

func NewDeleteCommand() cli.Command {
	return newDeleteCommand(common_cli.DefaultEnv)
}

func newDeleteCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(deleteCommand))
}

type deleteCommand struct {
	// SPIFFE ID of the trust domain to delete
	id string
}

func (c *deleteCommand) Name() string {
	return "federation delete"
}

func (c *deleteCommand) Synopsis() string {
	return "Deletes a dynamic federation relationship"
}

func (c *deleteCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
}

func (c *deleteCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if c.id == "" {
		return errors.New("id is required")
	}

	id, err := idutil.NormalizeSpiffeID(c.id, idutil.AllowAnyTrustDomain())
	if err != nil {
		return err
	}

	trustDomainClient := serverClient.NewTrustDomainClient()
	resp, err := trustDomainClient.BatchDeleteFederationRelationship(ctx, &trustdomain.BatchDeleteFederationRelationshipRequest{
		TrustDomains: []string{id},
	})
	if err != nil {
		return fmt.Errorf("failed to delete federation relationship: %w", err)
	}

	result := resp.Results[0]
	switch result.Status.Code {
	case int32(codes.OK):
		env.Println("federation relationship deleted.")
		return nil
	default:
		return fmt.Errorf("failed to delete federation relationship %q: %s", result.TrustDomain, result.Status.Message)
	}
}
