package agent

import (
	"context"
	"errors"
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/server/api"
)

type banCommand struct {
	// SPIFFE ID of agent being banned
	spiffeID string
}

// NewBanCommand creates a new "ban" subcommand for "agent" command.
func NewBanCommand() cli.Command {
	return NewBanCommandWithEnv(common_cli.DefaultEnv)
}

// NewBanCommandWithEnv creates a new "ban" subcommand for "agent" command
// using the environment specified
func NewBanCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(banCommand))
}

func (*banCommand) Name() string {
	return "agent ban"
}

func (*banCommand) Synopsis() string {
	return "Ban an attested agent given its SPIFFE ID"
}

// Run ban an agent given its SPIFFE ID
func (c *banCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if c.spiffeID == "" {
		return errors.New("a SPIFFE ID is required")
	}

	id, err := spiffeid.FromString(c.spiffeID)
	if err != nil {
		return err
	}

	agentClient := serverClient.NewAgentClient()
	if _, err := agentClient.BanAgent(ctx, &agentv1.BanAgentRequest{
		Id: api.ProtoFromID(id),
	}); err != nil {
		return err
	}

	return env.Println("Agent banned successfully")
}

func (c *banCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "The SPIFFE ID of the agent to ban (agent identity)")
}
