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
	"google.golang.org/grpc/status"
)

func NewRefreshCommand() cli.Command {
	return newRefreshCommand(common_cli.DefaultEnv)
}

func newRefreshCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(refreshCommand))
}

type refreshCommand struct {
	id string
}

func (c *refreshCommand) Name() string {
	return "federation refresh"
}

func (c *refreshCommand) Synopsis() string {
	return "Refreshes the bundle from the specified federated trust domain"
}

func (c *refreshCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
}

func (c *refreshCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if c.id == "" {
		return errors.New("id is required")
	}

	id, err := idutil.NormalizeSpiffeID(c.id, idutil.AllowAnyTrustDomain())
	if err != nil {
		return err
	}

	trustDomainClient := serverClient.NewTrustDomainClient()
	_, err = trustDomainClient.RefreshBundle(ctx, &trustdomain.RefreshBundleRequest{
		TrustDomain: id,
	})
	switch status.Code(err) {
	case codes.OK:
		env.Println("Bundle refreshed")
		return nil
	case codes.NotFound:
		return fmt.Errorf("there is no federation relationship with trust domain %q", id)
	default:
		return fmt.Errorf("failed to refresh bundle: %w", err)
	}
}
