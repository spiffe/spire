package federation

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	serverutil "github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
)

// NewUpdateCommand creates a new "update" subcommand for "federation" command.
func NewUpdateCommand() cli.Command {
	return newUpdateCommand(commoncli.DefaultEnv)
}

func newUpdateCommand(env *commoncli.Env) cli.Command {
	return serverutil.AdaptCommand(env, &updateCommand{env: env})
}

type updateCommand struct {
	path                    string
	config                  *federationRelationshipConfig
	env                     *commoncli.Env
	printer                 cliprinter.Printer
	federationRelationships []*types.FederationRelationship
}

func (*updateCommand) Name() string {
	return "federation update"
}

func (*updateCommand) Synopsis() string {
	return "Updates a dynamic federation relationship with a foreign trust domain"
}

func (c *updateCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.path, "data", "", "Path to a file containing federation relationships in JSON format (optional). If set to '-', read the JSON from stdin.")
	c.config = &federationRelationshipConfig{}
	appendConfigFlags(c.config, f)
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, c.prettyPrintUpdate)
}

func (c *updateCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient serverutil.ServerClient) error {
	federationRelationships, err := getRelationships(c.config, c.path)
	if err != nil {
		return err
	}
	c.federationRelationships = federationRelationships

	client := serverClient.NewTrustDomainClient()

	resp, err := client.BatchUpdateFederationRelationship(ctx, &trustdomainv1.BatchUpdateFederationRelationshipRequest{
		FederationRelationships: c.federationRelationships,
	})
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func (c *updateCommand) prettyPrintUpdate(env *commoncli.Env, results ...any) error {
	updateResp, ok := results[0].(*trustdomainv1.BatchUpdateFederationRelationshipResponse)
	if !ok || len(c.federationRelationships) < len(updateResp.Results) {
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	// Process results
	var succeeded []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result
	var failed []*trustdomainv1.BatchUpdateFederationRelationshipResponse_Result
	for i, r := range updateResp.Results {
		switch r.Status.Code {
		case int32(codes.OK):
			succeeded = append(succeeded, r)
		default:
			// The trust domain API does not include in the results the relationships that
			// failed to be updated, so we populate them from the request data.
			r.FederationRelationship = c.federationRelationships[i]
			failed = append(failed, r)
		}
	}

	// Print federation relationships that succeeded to be updated
	for _, r := range succeeded {
		env.Println()
		printFederationRelationship(r.FederationRelationship, env.Printf)
	}

	// Print federation relationships that failed to be updated
	for _, r := range failed {
		env.Println()
		env.ErrPrintf("Failed to update the following federation relationship (code: %s, msg: %q):\n",
			util.MustCast[codes.Code](r.Status.Code),
			r.Status.Message)
		printFederationRelationship(r.FederationRelationship, env.ErrPrintf)
	}

	if len(failed) > 0 {
		return errors.New("failed to update one or more federation relationships")
	}

	return nil
}
