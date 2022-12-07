package agent

import (
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"golang.org/x/net/context"
)

type countCommand struct {
	env     *commoncli.Env
	printer cliprinter.Printer
}

// NewCountCommand creates a new "count" subcommand for "agent" command.
func NewCountCommand() cli.Command {
	return NewCountCommandWithEnv(commoncli.DefaultEnv)
}

// NewCountCommandWithEnv creates a new "count" subcommand for "agent" command
// using the environment specified.
func NewCountCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &countCommand{env: env})
}

func (*countCommand) Name() string {
	return "agent count"
}

func (*countCommand) Synopsis() string {
	return "Count attested agents"
}

// Run counts attested agents
func (c *countCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	agentClient := serverClient.NewAgentClient()
	countResponse, err := agentClient.CountAgents(ctx, &agentv1.CountAgentsRequest{})
	if err != nil {
		return err
	}

	return c.printer.PrintProto(countResponse)
}

func (c *countCommand) AppendFlags(fs *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintCount)
}

func prettyPrintCount(env *commoncli.Env, results ...interface{}) error {
	countResp, ok := results[0].(*agentv1.CountAgentsResponse)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}
	count := int(countResp.Count)
	msg := fmt.Sprintf("%d attested ", count)
	msg = util.Pluralizer(msg, "agent", "agents", count)
	env.Println(msg)
	return nil
}
