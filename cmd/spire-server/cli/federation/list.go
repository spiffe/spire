package federation

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

func NewListCommand() cli.Command {
	return newListCommand(commoncli.DefaultEnv)
}

func newListCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &listCommand{env: env})
}

type listCommand struct {
	env     *commoncli.Env
	printer cliprinter.Printer
}

func (c *listCommand) Name() string {
	return "federation list"
}

func (c *listCommand) Synopsis() string {
	return "Lists all dynamic federation relationships"
}

func (c *listCommand) AppendFlags(fs *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintList)
}

func (c *listCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	trustDomainClient := serverClient.NewTrustDomainClient()

	resp, err := trustDomainClient.ListFederationRelationships(ctx, &trustdomainv1.ListFederationRelationshipsRequest{})
	if err != nil {
		return fmt.Errorf("error listing federation relationship: %w", err)
	}
	return c.printer.PrintProto(resp)
}

func prettyPrintList(env *commoncli.Env, results ...interface{}) error {
	listResp, ok := results[0].(*trustdomainv1.ListFederationRelationshipsResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	msg := fmt.Sprintf("Found %v ", len(listResp.FederationRelationships))
	msg = util.Pluralizer(msg, "federation relationship", "federation relationships", len(listResp.FederationRelationships))

	env.Println(msg)
	for _, fr := range listResp.FederationRelationships {
		env.Println()
		printFederationRelationship(fr, env.Printf)
	}

	return nil
}
