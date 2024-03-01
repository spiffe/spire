package logger

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/mitchellh/cli"
	api "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	apitype "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/cmd/spire-server/util"
	serverlogger "github.com/spiffe/spire/pkg/server/api/logger/v1"
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
	fs.StringVar(&c.newLevel, "level", "", "The new log level, one of (panic, fatal, error, warn, info, debug, trace, launch)")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintLogger)
}


// The routine that executes the command
func (c *setCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if c.newLevel == "" {
		return fmt.Errorf("a value (-level) must be set")
	}
	level := strings.ToLower(c.newLevel)
	var logger *apitype.Logger
	var err error
	if level == "launch" {
		logger, err = serverClient.NewLoggerClient().ResetLogLevel(ctx, &api.ResetLogLevelRequest{})
	} else {
		logrusLevel, err := logrus.ParseLevel(level)
		if err != nil {
			return fmt.Errorf("the value %s is not a valid setting", c.newLevel)
		}
		apiLevel, found := serverlogger.ApiLevel[logrusLevel]
		if !found {
			return fmt.Errorf("the logrus level %d could not be transformed into an api log level", logrusLevel)
		}
		logger, err = serverClient.NewLoggerClient().SetLogLevel(ctx, &api.SetLogLevelRequest{
			NewLevel: apiLevel,
		})
	}
	if err != nil {
		return fmt.Errorf("error fetching logger: %w", err)
	}
	return c.printer.PrintProto(logger)
}

func (l* setCommand) prettyPrintLogger(env *commoncli.Env, results ...any) error {
	return PrettyPrintLogger(env, results...)
}
