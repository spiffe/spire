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
	"google.golang.org/grpc/codes"
)

func NewDeleteCommand() cli.Command {
	return newDeleteCommand(commoncli.DefaultEnv)
}

func newDeleteCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &deleteCommand{env: env})
}

type deleteCommand struct {
	// SPIFFE ID of the trust domain to delete
	id      string
	env     *commoncli.Env
	printer cliprinter.Printer
}

func (c *deleteCommand) Name() string {
	return "federation delete"
}

func (c *deleteCommand) Synopsis() string {
	return "Deletes a dynamic federation relationship"
}

func (c *deleteCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.id, "id", "", "SPIFFE ID of the trust domain")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintDelete)
}

func (c *deleteCommand) Run(ctx context.Context, env *commoncli.Env, serverClient util.ServerClient) error {
	if c.id == "" {
		return errors.New("id is required")
	}

	trustDomainClient := serverClient.NewTrustDomainClient()
	resp, err := trustDomainClient.BatchDeleteFederationRelationship(ctx, &trustdomain.BatchDeleteFederationRelationshipRequest{
		TrustDomains: []string{c.id},
	})
	if err != nil {
		return fmt.Errorf("failed to delete federation relationship: %w", err)
	}
	return c.printer.PrintProto(resp)
}

func prettyPrintDelete(env *commoncli.Env, results ...interface{}) error {
	if deleteResp, ok := results[0].(*trustdomain.BatchDeleteFederationRelationshipResponse); ok && len(deleteResp.Results) > 0 {
		result := deleteResp.Results[0]
		switch result.Status.Code {
		case int32(codes.OK):
			env.Println("federation relationship deleted.")
			return nil
		default:
			return fmt.Errorf("failed to delete federation relationship %q: %s", result.TrustDomain, result.Status.Message)
		}
	}

	return cliprinter.ErrInternalCustomPrettyFunc
}
