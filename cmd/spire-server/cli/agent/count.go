package agent

import (
	"flag"
	"fmt"

	"github.com/mitchellh/cli"

	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/api/server/agent/v1"

	"golang.org/x/net/context"
)

type countCommand struct{}

// NewCountCommand creates a new "count" subcommand for "agent" command.
func NewCountCommand() cli.Command {
	return NewCountCommandWithEnv(common_cli.DefaultEnv)
}

// NewCountCommandWithEnv creates a new "count" subcommand for "agent" command
// using the environment specified.
func NewCountCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(countCommand))
}

func (*countCommand) Name() string {
	return "agent count"
}

func (countCommand) Synopsis() string {
	return "Count attested agents"
}

//Run counts attested agents
func (c *countCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	agentClient := serverClient.NewAgentClient()
	countResponse, err := agentClient.CountAgents(ctx, &agent.CountAgentsRequest{})
	if err != nil {
		return err
	}

	count := int(countResponse.Count)
	msg := fmt.Sprintf("%d attested ", count)
	msg = util.Pluralizer(msg, "agent", "agents", count)
	env.Println(msg)

	return nil
}

func (c *countCommand) AppendFlags(fs *flag.FlagSet) {
}
