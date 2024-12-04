package validate

import (
	"context"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/cli/run"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server"
)

const commandName = "validate"

func NewValidateCommand() cli.Command {
	return newValidateCommand(commoncli.DefaultEnv)
}

func newValidateCommand(env *commoncli.Env) *validateCommand {
	return &validateCommand{
		env: env,
	}
}

type validateCommand struct {
	env *commoncli.Env
}

// Help prints the server cmd usage
func (c *validateCommand) Help() string {
	return run.Help(commandName, c.env.Stderr)
}

func (c *validateCommand) Synopsis() string {
	return "Validates a SPIRE server configuration file"
}

func (c *validateCommand) Run(args []string) int {
	config, err := run.LoadConfig(commandName, args, []log.Option{log.WithOutputFile("/dev/null")}, c.env.Stderr, false)

	if err != nil {
		// Ignore error since a failure to write to stderr cannot very well be reported
		_ = c.env.ErrPrintf("SPIRE server configuration file is invalid: %v\n", err)
		return 1
	}

	s := server.New(*config)

	err = s.ValidateConfig(context.Background())
	if err != nil {
		_ = c.env.ErrPrintf("SPIRE server configuration file is invalid: %v\n", err)
		return 1
	}
	_ = c.env.Println("SPIRE server configuration file is valid.")
	return 0
}
