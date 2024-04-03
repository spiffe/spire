package logger

import (
	"context"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	api "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

type resetCommand struct {
	env     *commoncli.Env
	printer cliprinter.Printer
}

// Returns a cli.command that sets the log level using the default
// cli environment.
func NewResetCommand() cli.Command {
	return NewResetCommandWithEnv(commoncli.DefaultEnv)
}

// Returns a cli.command that sets the log level.
func NewResetCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &resetCommand{env: env})
}

// The name of the command.
func (*resetCommand) Name() string {
	return "logger reset"
}

// The help presented description of the command.
func (*resetCommand) Synopsis() string {
	return "Reset the logger details to launch level"
}

// Adds additional flags specific to the command.
func (c *resetCommand) AppendFlags(fs *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintLogger)
}

// The routine that executes the command
func (c *resetCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	logger, err := serverClient.NewLoggerClient().ResetLogLevel(ctx, &api.ResetLogLevelRequest{})
	if err != nil {
		return fmt.Errorf("failed to reset logger: %w", err)
	}
	return c.printer.PrintProto(logger)
}

func (c *resetCommand) prettyPrintLogger(env *commoncli.Env, results ...any) error {
	return PrettyPrintLogger(env, results...)
}
