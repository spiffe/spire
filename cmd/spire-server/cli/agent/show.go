package agent

import (
	"errors"
	"flag"

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
	env *commoncli.Env
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
	return util.AdaptCommand(env, &showCommand{env: env})
}

func (*showCommand) Name() string {
	return "agent show"
}

func (*showCommand) Synopsis() string {
	return "Shows the details of an attested agent given its SPIFFE ID"
}

// Run shows an agent given its SPIFFE ID
func (c *showCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
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

	return c.printer.PrintProto(agent)
}

func (c *showCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "The SPIFFE ID of the agent to show (agent identity)")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintAgent)
}

func prettyPrintAgent(env *commoncli.Env, results ...any) error {
	agent, ok := results[0].(*types.Agent)
	if !ok {
		return errors.New("internal error: cli printer; please report this bug")
	}

	env.Printf("Found an attested agent given its SPIFFE ID\n\n")
	if err := printAgents(env, agent); err != nil {
		return err
	}

	for _, s := range agent.Selectors {
		env.Printf("Selectors         : %s:%s\n", s.Type, s.Value)
	}
	return nil
}
