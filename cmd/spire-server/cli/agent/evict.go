package agent

import (
	"errors"
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/server/api"
	"golang.org/x/net/context"
)

type evictCommand struct {
	env *commoncli.Env
	// SPIFFE ID of the agent being evicted
	spiffeID string
	printer  cliprinter.Printer
}

// NewEvictCommand creates a new "evict" subcommand for "agent" command.
func NewEvictCommand() cli.Command {
	return NewEvictCommandWithEnv(commoncli.DefaultEnv)
}

// NewEvictCommandWithEnv creates a new "evict" subcommand for "agent" command
// using the environment specified
func NewEvictCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &evictCommand{env: env})
}

func (*evictCommand) Name() string {
	return "agent evict"
}

func (*evictCommand) Synopsis() string {
	return "Evicts an attested agent given its SPIFFE ID"
}

// Run evicts an agent given its SPIFFE ID
func (c *evictCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if c.spiffeID == "" {
		return errors.New("a SPIFFE ID is required")
	}

	id, err := spiffeid.FromString(c.spiffeID)
	if err != nil {
		return err
	}

	agentClient := serverClient.NewAgentClient()
	delAgentResponse, err := agentClient.DeleteAgent(ctx, &agentv1.DeleteAgentRequest{Id: api.ProtoFromID(id)})
	if err != nil {
		return err
	}

	return c.printer.PrintProto(delAgentResponse)
}

func (c *evictCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "The SPIFFE ID of the agent to evict (agent identity)")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintEvictResult)
}

func prettyPrintEvictResult(env *commoncli.Env, _ ...interface{}) error {
	env.Println("Agent evicted successfully")
	return nil
}
