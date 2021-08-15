package agent

import (
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"

	"golang.org/x/net/context"
)

type listCommand struct{}

// NewListCommand creates a new "list" subcommand for "agent" command.
func NewListCommand() cli.Command {
	return NewListCommandWithEnv(common_cli.DefaultEnv)
}

// NewListCommandWithEnv creates a new "list" subcommand for "agent" command
// using the environment specified
func NewListCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(listCommand))
}

func (*listCommand) Name() string {
	return "agent list"
}

func (listCommand) Synopsis() string {
	return "Lists attested agents and their SPIFFE IDs"
}

// Run lists attested agents
func (c *listCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	agentClient := serverClient.NewAgentClient()
	pageToken := ""
	moreResults := true
	numResponseAgents := 0
	var responseAgents []*types.Agent
	var listResponse *agentv1.ListAgentsResponse
	var err error

	for moreResults {
		listResponse, err = agentClient.ListAgents(ctx, &agentv1.ListAgentsRequest{
			PageSize:  1396, // ~80% of (4 MB/theoretical maximum size of 1 agent in MB)
			PageToken: pageToken,
		})
		if err != nil {
			return err
		}

		pageToken = listResponse.NextPageToken
		moreResults = pageToken != ""

		numResponseAgents += len(listResponse.Agents)
		responseAgents = append(responseAgents, listResponse.Agents...)
	}

	if numResponseAgents == 0 {
		return env.Printf("No attested agents found\n")
	}

	msg := fmt.Sprintf("Found %d attested ", numResponseAgents)
	msg = util.Pluralizer(msg, "agent", "agents", numResponseAgents)
	env.Printf(msg + ":\n\n")

	return printAgents(env, responseAgents...)
}

func (c *listCommand) AppendFlags(fs *flag.FlagSet) {
}

func printAgents(env *common_cli.Env, agents ...*types.Agent) error {
	for _, agent := range agents {
		id, err := spiffeid.New(agent.Id.TrustDomain, agent.Id.Path)
		if err != nil {
			return err
		}

		if err := env.Printf("SPIFFE ID         : %s\n", id.String()); err != nil {
			return err
		}
		if err := env.Printf("Attestation type  : %s\n", agent.AttestationType); err != nil {
			return err
		}
		if err := env.Printf("Expiration time   : %s\n", time.Unix(agent.X509SvidExpiresAt, 0)); err != nil {
			return err
		}
		// Banned agents will have an empty serial number
		if agent.Banned {
			if err := env.Printf("Banned            : %t\n", agent.Banned); err != nil {
				return err
			}
		} else {
			if err := env.Printf("Serial number     : %s\n", agent.X509SvidSerialNumber); err != nil {
				return err
			}
		}
		if err := env.Println(); err != nil {
			return err
		}
	}

	return nil
}
