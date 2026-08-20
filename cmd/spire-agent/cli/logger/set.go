package logger

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/mitchellh/cli"
	"github.com/sirupsen/logrus"
	api "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/logger/v1"
	"github.com/spiffe/spire/cmd/spire-agent/util"
	commonlogger "github.com/spiffe/spire/pkg/common/api/logger"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

type setCommand struct {
	env      *commoncli.Env
	newLevel string
	printer  cliprinter.Printer
}

// Returns a cli.Command that sets the log level using the default cli environment.
func NewSetCommand() cli.Command {
	return NewSetCommandWithEnv(commoncli.DefaultEnv)
}

// Returns a cli.Command that sets the log level.
func NewSetCommandWithEnv(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &setCommand{env: env})
}

func (*setCommand) Name() string {
	return "logger set"
}

func (*setCommand) Synopsis() string {
	return "Sets the logger details"
}

func (c *setCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.newLevel, "level", "", "The new log level, one of (panic, fatal, error, warn, info, debug, trace)")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintLogger)
}

func (c *setCommand) Run(ctx context.Context, _ *commoncli.Env, agentClient util.AgentClient) error {
	if c.newLevel == "" {
		return errors.New("a value (-level) must be set")
	}

	level := strings.ToLower(c.newLevel)
	logrusLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("the value %q is not a valid setting", c.newLevel)
	}

	apiLevel, found := commonlogger.APILevel[logrusLevel]
	if !found {
		return fmt.Errorf("the logrus level %q could not be transformed into an api log level", level)
	}
	logger, err := agentClient.NewLoggerClient().SetLogLevel(ctx, &api.SetLogLevelRequest{
		NewLevel: apiLevel,
	})
	if err != nil {
		return fmt.Errorf("failed to set log level: %w", err)
	}

	return c.printer.PrintProto(logger)
}

func (c *setCommand) prettyPrintLogger(env *commoncli.Env, results ...any) error {
	return commonlogger.PrettyPrintLogger(env, results...)
}
