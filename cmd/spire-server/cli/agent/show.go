package agent

import (
	"errors"
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire/types"

	"golang.org/x/net/context"
)

type showCommand struct {
	// SPIFFE ID of the agent being showed
	spiffeID string
}

// NewShowCommand creates a new "show" subcommand for "agent" command.
func NewShowCommand() cli.Command {
	return newShowCommand(common_cli.DefaultEnv, util.NewClients)
}

func newShowCommand(env *common_cli.Env, clientsMaker util.ClientsMaker) cli.Command {
	return util.AdaptCommand(env, clientsMaker, new(showCommand))
}

func (*showCommand) Name() string {
	return "agent show"
}

func (showCommand) Synopsis() string {
	return "Shows the details of an attested agent given its SPIFFE ID"
}

//Run shows an agent given its SPIFFE ID
func (c *showCommand) Run(ctx context.Context, env *common_cli.Env, clients *util.Clients) error {
	if c.spiffeID == "" {
		return errors.New("a SPIFFE ID is required")
	}

	id, err := spiffeid.FromString(c.spiffeID)
	if err != nil {
		return err
	}

	agent, err := clients.AgentClient.GetAgent(ctx, &agent.GetAgentRequest{Id: api.ProtoFromID(id)})
	if err != nil {
		return err
	}

	env.Printf("Found an attested agent given its SPIFFE ID\n\n")

	if err := printAgents([]*types.Agent{agent}, env); err != nil {
		return err
	}

	return nil
}

func (c *showCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "The SPIFFE ID of the agent to show (agent identity)")
}
