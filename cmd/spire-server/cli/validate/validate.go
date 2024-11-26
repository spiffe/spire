package validate

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/cli/run"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server"
)

const commandName = "validate"

func NewValidateCommand(ctx context.Context, logOptions []log.Option) cli.Command {
	return newValidateCommand(ctx, commoncli.DefaultEnv, logOptions)
}

func newValidateCommand(ctx context.Context, env *commoncli.Env, logOptions []log.Option) *validateCommand {
	return &validateCommand{
		ctx:        ctx,
		env:        env,
		logOptions: logOptions,
	}
}

type validateCommand struct {
	ctx        context.Context
	logOptions []log.Option
	env        *commoncli.Env
	printer    cliprinter.Printer
}

// Help prints the server cmd usage
func (c *validateCommand) Help() string {
	return run.Help(commandName, c.env.Stderr, c.SetupPrinter)
}

func (c *validateCommand) Synopsis() string {
	return "Validates a SPIRE server configuration file"
}

func (c *validateCommand) SetupPrinter(flags *flag.FlagSet) {
	cliprinter.AppendFlagWithCustomPretty(&c.printer, flags, c.env, c.prettyPrintValidate)
}

func (c *validateCommand) Run(args []string) int {
	config, err := run.LoadConfig(commandName, args, c.logOptions, c.env.Stderr, false, c.SetupPrinter)
	if err != nil {
		_, _ = fmt.Fprintln(c.env.Stderr, err)
		return 1
	}
	config.ValidateOnly = true

	// Set umask before starting up the server
	commoncli.SetUmask(config.Log)

	s := server.New(config)

	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	err = s.Run(ctx)
	if err != nil {
		config.Log.WithError(err).Error("Validation failed: validation server crashed")
		return 1
	}

	err = c.printer.PrintStruct(&validateResult{
		Valid: config.ValidationError == "",
		Error: config.ValidationError,
		Notes: config.ValidationNotes,
	})
	if err != nil {
		return 1
	}
	return 0
}

type validateResult struct {
	Valid bool     `json:"valid"`
	Error string   `json:"error"`
	Notes []string `json:"notes"`
}

func (c *validateCommand) prettyPrintValidate(env *commoncli.Env, results ...any) error {
	if resultInterface, ok := results[0].([]any); ok {
		result, ok := resultInterface[0].(*validateResult)
		if !ok {
			return errors.New("unexpected type")
		}
		// pretty print error section
		if !result.Valid {
			if err := env.Printf("Validation error:\n"); err != nil {
				return err
			}
			if err := env.Printf("  %s\n", result.Error); err != nil {
				return err
			}
		}
		// pretty print notes section
		if len(result.Notes) < 1 {
			if err := env.Printf("No validation notes\n"); err != nil {
				return err
			}
			return nil
		}
		if err := env.Printf("Validation notes:\n"); err != nil {
			return err
		}
		for _, note := range result.Notes {
			if err := env.Printf("  %s\n", note); err != nil {
				return err
			}
		}
	}
	return cliprinter.ErrInternalCustomPrettyFunc
}
