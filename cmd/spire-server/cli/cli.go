package cli

import (
	"log"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/cli/register"
	"github.com/spiffe/spire/cmd/spire-server/cli/run"
	"github.com/spiffe/spire/cmd/spire-server/cli/token"
)

func Run(args []string) int {
	c := cli.NewCLI("spire-server", "0.0.1") //TODO expose version configuration
	c.Args = args
	c.Commands = map[string]cli.CommandFactory{
		"run": func() (cli.Command, error) {
			return &run.RunCLI{}, nil
		},
		"register": func() (cli.Command, error) {
			return &register.RegisterCLI{}, nil
		},
		"token generate": func() (cli.Command, error) {
			return &token.GenerateCLI{}, nil
		},
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}
	return exitStatus
}
