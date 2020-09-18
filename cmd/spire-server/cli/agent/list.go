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

type listCommand struct {
	agents []*types.Agent
}

// NewListCommand creates a new "list" subcommand for "agent" command.
func NewListCommand() cli.Command {
	return newListCommand(common_cli.DefaultEnv, util.NewClients)
}

func newListCommand(env *common_cli.Env, clientsMaker util.ClientsMaker) cli.Command {
	return util.AdaptCommand(env, clientsMaker, new(listCommand))
}

func (*listCommand) Name() string {
	return "agent list"
}

func (listCommand) Synopsis() string {
	return "Lists attested agents and their SPIFFE IDs"
}

//Run lists attested agents
func (c *listCommand) Run(ctx context.Context, env *common_cli.Env, clients *util.Clients) error {
	listResponse, err := clients.AgentClient.ListAgents(ctx, &agent.ListAgentsRequest{})
	if err != nil {
		return err
	}
	c.agents = listResponse.Agents
	if len(c.agents) == 0 {
		return env.Printf("No attested agents found\n")
	}

	msg := fmt.Sprintf("Found %d attested ", len(c.agents))
	msg = util.Pluralizer(msg, "agent", "agents", len(c.agents))
	env.Printf(msg + ":\n\n")

	return printAgents(c.agents, env)
}

func (c *listCommand) AppendFlags(fs *flag.FlagSet) {
}

func printAgents(agents []*types.Agent, env *common_cli.Env) error {
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
