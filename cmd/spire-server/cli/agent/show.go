package agent

import (
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/server/api"
	"golang.org/x/net/context"
)

type showCommand struct {
	// SPIFFE ID of the agent being showed
	spiffeID string
	printer  cliprinter.Printer
}

// NewShowCommand creates a new "show" subcommand for "agent" command.
func NewShowCommand() cli.Command {
	return NewShowCommandWithEnv(commoncli.DefaultEnv)
}

// NewShowCommandWithEnv creates a new "show" subcommand for "agent" command
// using the environment specified
func NewShowCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, new(showCommand))
}

func (*showCommand) Name() string {
	return "agent show"
}

func (showCommand) Synopsis() string {
	return "Shows the details of an attested agent given its SPIFFE ID"
}

// Run shows an agent given its SPIFFE ID
func (c *showCommand) Run(ctx context.Context, env *commoncli.Env, serverClient util.ServerClient) error {
	if c.spiffeID == "" {
		return errors.New("a SPIFFE ID is required")
	}

	id, err := spiffeid.FromString(c.spiffeID)
	if err != nil {
		return err
	}

	agentClient := serverClient.NewAgentClient()
	agent, err := agentClient.GetAgent(ctx, &agentv1.GetAgentRequest{Id: api.ProtoFromID(id)})
	if err != nil {
		return err
	}
	c.printer.MustPrintProto(agent)

	return nil
}

func (c *showCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "The SPIFFE ID of the agent to show (agent identity)")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, prettyPrintAgent)
}

func prettyPrintAgent(results ...interface{}) error {
	agent := results[0].(*types.Agent)

	fmt.Printf("Found an attested agent given its SPIFFE ID\n\n")
	if err := printAgents(agent); err != nil {
		return err
	}

	for _, s := range agent.Selectors {
		fmt.Printf("Selectors         : %s:%s\n", s.Type, s.Value)
	}
	return nil
}
