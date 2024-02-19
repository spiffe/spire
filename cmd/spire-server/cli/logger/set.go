package logger

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/mitchellh/cli"
	api "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

type setCommand struct {
	env               *commoncli.Env
	newLevel          string
	printer           cliprinter.Printer
}

// Returns a cli.command that sets the log level using the default
// cli enviornment.
func NewSetCommand() cli.Command {
	return NewSetCommandWithEnv(commoncli.DefaultEnv)
}

// Returns a cli.command that sets the log level.
func NewSetCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &setCommand{env: env})
}

// The name of the command.
func (_ *setCommand) Name() string {
	return "logger set"
}

// The help presented description of the command.
func (_ *setCommand) Synopsis() string {
	return "Sets the logger details"
}

// Adds additional flags specific to the command.
func (c *setCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.newLevel, "level", "", "The new log level, one of (panic, fatal, error, warn, info, debug, trace, default)")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintLogger)
}


// The routine that executes the command
func (c *setCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if c.newLevel != "" {
		fmt.Errorf("the newLevel is %s", c.newLevel)
		grpc_key := strings.ToUpper(c.newLevel)
		value, found := api.SetLogLevelRequest_SetValue_value[grpc_key]
		if !found {
			return fmt.Errorf("the value %s is not a valid setting", c.newLevel)
		}

		logger, err := serverClient.NewLoggerClient().SetLogLevel(ctx, &api.SetLogLevelRequest{
			SetLevel: api.SetLogLevelRequest_SetValue(value),
		})
		if err != nil {
			return fmt.Errorf("error fetching logger: %w", err)
		}

		return c.printer.PrintProto(logger)
	}

	return fmt.Errorf("a value (-level) must be set")
}

func (l* setCommand) prettyPrintLogger(env *commoncli.Env, results ...any) error {
	return PrettyPrintLogger(env, results...)
}
