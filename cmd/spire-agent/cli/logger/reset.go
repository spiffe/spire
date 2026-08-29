package logger

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	api "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/logger/v1"
	"github.com/spiffe/spire/cmd/spire-agent/util"
	commonlogger "github.com/spiffe/spire/pkg/common/api/logger"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

type resetCommand struct {
	env     *commoncli.Env
	printer cliprinter.Printer
}

// Returns a cli.Command that resets the log level using the default cli environment.
func NewResetCommand() cli.Command {
	return NewResetCommandWithEnv(commoncli.DefaultEnv)
}

// Returns a cli.Command that resets the log level to the launch level.
func NewResetCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &resetCommand{env: env})
}

func (*resetCommand) Name() string {
	return "logger reset"
}

func (*resetCommand) Synopsis() string {
	return "Reset the logger details to launch level"
}

func (c *resetCommand) AppendFlags(fs *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintLogger)
}

func (c *resetCommand) Run(ctx context.Context, _ *commoncli.Env, agentClient util.AgentClient) error {
	logger, err := agentClient.NewLoggerClient().ResetLogLevel(ctx, &api.ResetLogLevelRequest{})
	if err != nil {
		return fmt.Errorf("failed to reset logger: %w", err)
	}
	return c.printer.PrintProto(logger)
}

func (c *resetCommand) prettyPrintLogger(env *commoncli.Env, results ...any) error {
	return commonlogger.PrettyPrintLogger(env, results...)
}
