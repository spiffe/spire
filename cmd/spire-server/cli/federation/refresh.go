package federation

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/server/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NewRefreshCommand() cli.Command {
	return newRefreshCommand(commoncli.DefaultEnv)
}

func newRefreshCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &refreshCommand{env: env})
}

type refreshCommand struct {
	id      string
	env     *commoncli.Env
	printer cliprinter.Printer
}

func (c *refreshCommand) Name() string {
	return "federation refresh"
}

func (c *refreshCommand) Synopsis() string {
	return "Refreshes the bundle from the specified federated trust domain"
}

func (c *refreshCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintRefresh)
}

func (c *refreshCommand) Run(ctx context.Context, env *commoncli.Env, serverClient util.ServerClient) error {
	if c.id == "" {
		return errors.New("id is required")
	}

	trustDomainClient := serverClient.NewTrustDomainClient()
	_, err := trustDomainClient.RefreshBundle(ctx, &trustdomain.RefreshBundleRequest{
		TrustDomain: c.id,
	})

	switch status.Code(err) {
	case codes.OK:
		return c.printer.PrintProto(api.OK())
	case codes.NotFound:
		return fmt.Errorf("there is no federation relationship with trust domain %q", c.id)
	default:
		return fmt.Errorf("failed to refresh bundle: %w", err)
	}
}

func prettyPrintRefresh(env *commoncli.Env, _ ...interface{}) error {
	return env.Println("Bundle refreshed")
}
