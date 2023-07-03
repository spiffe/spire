package federation

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"google.golang.org/grpc/codes"
)

const (
	profileHTTPSWeb    = "https_web"
	profileHTTPSSPIFFE = "https_spiffe"
)

// NewCreateCommand creates a new "create" subcommand for "federation" command.
func NewCreateCommand() cli.Command {
	return newCreateCommand(commoncli.DefaultEnv)
}

func newCreateCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &createCommand{env: env})
}

type createCommand struct {
	path                    string
	config                  *federationRelationshipConfig
	env                     *commoncli.Env
	printer                 cliprinter.Printer
	federationRelationships []*types.FederationRelationship
}

func (*createCommand) Name() string {
	return "federation create"
}

func (*createCommand) Synopsis() string {
	return "Creates a dynamic federation relationship with a foreign trust domain"
}

func (c *createCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.path, "data", "", "Path to a file containing federation relationships in JSON format (optional). If set to '-', read the JSON from stdin.")
	c.config = &federationRelationshipConfig{}
	appendConfigFlags(c.config, f)
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, c.prettyPrintCreate)
}

func (c *createCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	federationRelationships, err := getRelationships(c.config, c.path)
	if err != nil {
		return err
	}
	c.federationRelationships = federationRelationships

	client := serverClient.NewTrustDomainClient()

	resp, err := client.BatchCreateFederationRelationship(ctx, &trustdomainv1.BatchCreateFederationRelationshipRequest{
		FederationRelationships: federationRelationships,
	})
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	return c.printer.PrintProto(resp)
}

func (c *createCommand) prettyPrintCreate(env *commoncli.Env, results ...interface{}) error {
	createResp, ok := results[0].(*trustdomainv1.BatchCreateFederationRelationshipResponse)
	if !ok || len(c.federationRelationships) < len(createResp.Results) {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	// Process results
	var succeeded []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result
	var failed []*trustdomainv1.BatchCreateFederationRelationshipResponse_Result
	for i, r := range createResp.Results {
		switch r.Status.Code {
		case int32(codes.OK):
			succeeded = append(succeeded, r)
		default:
			// The trust domain API does not include in the results the relationships that
			// failed to be created, so we populate them from the request data.
			r.FederationRelationship = c.federationRelationships[i]
			failed = append(failed, r)
		}
	}

	// Print federation relationships that succeeded to be created
	for _, r := range succeeded {
		env.Println()
		printFederationRelationship(r.FederationRelationship, env.Printf)
	}

	// Print federation relationships that failed to be created
	for _, r := range failed {
		env.Println()
		env.ErrPrintf("Failed to create the following federation relationship (code: %s, msg: %q):\n",
			codes.Code(r.Status.Code),
			r.Status.Message)
		printFederationRelationship(r.FederationRelationship, env.ErrPrintf)
	}

	if len(failed) > 0 {
		return errors.New("failed to create one or more federation relationships")
	}

	return nil
}
