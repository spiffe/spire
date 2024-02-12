package logger

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/mitchellh/cli"
	api "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

type getCommand struct {
	env               *commoncli.Env
	printer           cliprinter.Printer
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

// The name of the command.
func (_ *getCommand) Name() string {
	return "logger get"
}

// The help presented description of the command.
func (_ *getCommand) Synopsis() string {
	return "Gets the logger details"
}

// Adds additional flags specific to the command.
func (c *getCommand) AppendFlags(fs *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, c.prettyPrintLogger)
}

// The routine that executes the command
func (c *getCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {

	logger, err := serverClient.NewLoggerClient().GetLogger(ctx, &api.GetLoggerRequest{})
	if err != nil {
		return fmt.Errorf("error fetching logger: %w", err)
	}

	return c.printer.PrintProto(logger)
}

// Formatting for the logger under pretty printing of output.
func (l* getCommand) prettyPrintLogger(env *commoncli.Env, results ...any) error {
	logger, ok := results[0].(*types.Logger)
	if !ok {
		return errors.New("internal error: logger not found; please report this as a bug")
	}
	if err := env.Printf("Logger Level : %s\n", logrus.Level(logger.CurrentLevel)); err != nil {
		return err
	}
	if err := env.Printf("Logger Default : %s\n", logrus.Level(logger.DefaultLevel)); err != nil {
		return err
	}
	if err := env.Println(); err != nil {
		return err
	}
	return nil
}

