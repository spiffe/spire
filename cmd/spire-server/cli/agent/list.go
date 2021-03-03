package agent

import (
	"flag"
	"fmt"
	"time"

	"github.com/mitchellh/cli"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire/types"

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

//Run lists attested agents
func (c *listCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	agentClient := serverClient.NewAgentClient()
	listResponse, err := agentClient.ListAgents(ctx, &agent.ListAgentsRequest{})
	if err != nil {
		return err
	}

	if len(listResponse.Agents) == 0 {
		return env.Printf("No attested agents found\n")
	}

	msg := fmt.Sprintf("Found %d attested ", len(listResponse.Agents))
	msg = util.Pluralizer(msg, "agent", "agents", len(listResponse.Agents))
	env.Printf(msg + ":\n\n")

	return printAgents(env, listResponse.Agents...)
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
		if err := env.Printf("Serial number     : %s\n", agent.X509SvidSerialNumber); err != nil {
			return err
		}
		if err := env.Println(); err != nil {
			return err
		}
	}

	return nil
}
