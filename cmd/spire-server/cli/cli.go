package cli

import (
	"log"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/cli/bundle"
	"github.com/spiffe/spire/cmd/spire-server/cli/entry"
	"github.com/spiffe/spire/cmd/spire-server/cli/run"
	"github.com/spiffe/spire/cmd/spire-server/cli/token"
)

func Run(args []string) int {
	c := cli.NewCLI("spire-server", "0.0.1") //TODO expose version configuration
	c.Args = args
	c.Commands = map[string]cli.CommandFactory{
		"bundle show": func() (cli.Command, error) {
			return bundle.NewShowCommand(), nil
		},
		"entry create": func() (cli.Command, error) {
			return &entry.CreateCLI{}, nil
		},
		"entry delete": func() (cli.Command, error) {
			return &entry.DeleteCLI{}, nil
		},
		"entry show": func() (cli.Command, error) {
			return &entry.ShowCLI{}, nil
		},
		"run": func() (cli.Command, error) {
			return &run.RunCLI{}, nil
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
