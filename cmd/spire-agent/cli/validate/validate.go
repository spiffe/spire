package validate

import (
	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-agent/cli/run"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

const commandName = "validate"

func NewValidateCommand() cli.Command {
	return newValidateCommand(common_cli.DefaultEnv)
}

func newValidateCommand(env *common_cli.Env) *validateCommand {
	return &validateCommand{
		env: env,
	}
}

type validateCommand struct {
	env *common_cli.Env
}

// Help prints the agent cmd usage
func (c *validateCommand) Help() string {
	return run.Help(commandName, c.env.Stderr)
}

func (c *validateCommand) Synopsis() string {
	return "Validates a SPIRE agent configuration file"
}

func (c *validateCommand) Run(args []string) int {
	if _, err := run.LoadConfig(commandName, args, nil, c.env.Stderr, false); err != nil {
		// Ignore error since a failure to write to stderr cannot very well be reported
		_ = c.env.ErrPrintf("SPIRE agent configuration file is invalid: %v\n", err)
		return 1
	}
	_ = c.env.Println("SPIRE agent configuration file is valid.")
	return 0
}
