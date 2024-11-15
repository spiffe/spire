package validate

import (
	"context"
	"fmt"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/cli/run"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
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
}

// Help prints the server cmd usage
func (c *validateCommand) Help() string {
	return run.Help(commandName, c.env.Stderr)
}

func (c *validateCommand) Synopsis() string {
	return "Validates a SPIRE server configuration file"
}

func (c *validateCommand) Run(args []string) int {
	config, err := run.LoadConfig(commandName, args, c.logOptions, c.env.Stderr, false)
	if err != nil {
		_, _ = fmt.Fprintln(c.env.Stderr, err)
		return 1
	}
	config.ValidateOnly = true

	// Set umask before starting up the server
	commoncli.SetUmask(config.Log)

	s := server.New(*config)

	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	err = s.Run(ctx)
	if err != nil {
		config.Log.WithError(err).Error("Validation failed: validation server crashed")
		return 1
	}

	fmt.Printf("status: %+v\n", config.ValidationNotes)
	fmt.Printf("error: %+v\n", config.ValidationInError)

	config.Log.Info("Validation server stopped gracefully")
	return 0
}
