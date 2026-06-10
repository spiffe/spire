package logger

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	api "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/logger/v1"
	"github.com/spiffe/spire/cmd/spire-agent/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

type getCommand struct {
	env     *commoncli.Env
	printer cliprinter.Printer
}

// Returns a cli.command that gets the logger information using
// the default cli environment.
func NewGetCommand() cli.Command {
	return NewGetCommandWithEnv(commoncli.DefaultEnv)
}

// Returns a cli.command that gets the root logger information.
func NewGetCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &getCommand{env: env})
}

func (*getCommand) Name() string {
	return "logger get"
}

func (*getCommand) Synopsis() string {
	return "Gets the logger details"
}

func (c *getCommand) AppendFlags(fs *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintLogger)
}

func (c *getCommand) Run(ctx context.Context, _ *commoncli.Env, agentClient util.AgentClient) error {
	logger, err := agentClient.NewLoggerClient().GetLogger(ctx, &api.GetLoggerRequest{})
	if err != nil {
		return fmt.Errorf("error fetching logger: %w", err)
	}

	return c.printer.PrintProto(logger)
}

func (c *getCommand) prettyPrintLogger(env *commoncli.Env, results ...any) error {
	return PrettyPrintLogger(env, results...)
}
