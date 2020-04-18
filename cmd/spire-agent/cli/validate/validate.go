package validate

import (
	"flag"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-agent/cli/run"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

const defaultConfigPath = "agent.conf"

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

	configPath string
	ExpandEnv  bool
}

func (c *validateCommand) Help() string {
	// ignoring parsing errors since "-h" is always supported by the flags package
	_ = c.parseFlags([]string{"-h"})
	return ""
}

func (c *validateCommand) Synopsis() string {
	return "Validates a SPIRE agent configuration file"
}

func (c *validateCommand) Run(args []string) int {
	if err := c.parseFlags(args); err != nil {
		return 1
	}
	if err := c.run(); err != nil {
		// Ignore error since a failure to write to stderr cannot very well be reported
		_ = c.env.ErrPrintf("SPIRE agent configuration file is invalid: %v\n", err)
		return 1
	}
	_ = c.env.Println("SPIRE agent configuration file is valid.")
	return 0
}

func (c *validateCommand) parseFlags(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(c.env.Stderr)
	fs.StringVar(&c.configPath, "config", defaultConfigPath, "Path to a SPIRE agent configuration file")
	fs.BoolVar(&c.ExpandEnv, "expandEnv", false, "Expand environment variables in SPIRE config file")
	return fs.Parse(args)
}

func (c *validateCommand) run() error {
	fileInput, err := run.ParseFile(c.configPath, c.ExpandEnv)
	if err != nil {
		return err
	}

	if _, err := run.NewAgentConfig(fileInput, nil); err != nil {
		return err
	}

	return nil
}
