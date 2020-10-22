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

	"golang.org/x/net/context"
)

type evictCommand struct {
	// SPIFFE ID of the agent being evicted
	spiffeID string
}

// NewEvictCommand creates a new "evict" subcommand for "agent" command.
func NewEvictCommand() cli.Command {
	return NewEvictCommandWithEnv(common_cli.DefaultEnv)
}

// NewEvictCommandWithEnv creates a new "evict" subcommand for "agent" command
// using the environment specified
func NewEvictCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(evictCommand))
}

func (*evictCommand) Name() string {
	return "agent evict"
}

func (evictCommand) Synopsis() string {
	return "Evicts an attested agent given its SPIFFE ID"
}

//Run evicts an agent given its SPIFFE ID
func (c *evictCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if c.spiffeID == "" {
		return errors.New("a SPIFFE ID is required")
	}

	id, err := spiffeid.FromString(c.spiffeID)
	if err != nil {
		return err
	}

	agentClient := serverClient.NewAgentClient()
	_, err = agentClient.DeleteAgent(ctx, &agent.DeleteAgentRequest{Id: api.ProtoFromID(id)})
	if err != nil {
		return err
	}

	return env.Println("Agent evicted successfully")
}

func (c *evictCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "The SPIFFE ID of the agent to evict (agent identity)")
}
