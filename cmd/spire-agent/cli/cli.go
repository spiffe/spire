package cli

import (
	"log"
	"os"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-agent/cli/command"
)

func Run(args []string) int {

	c := cli.NewCLI("sri/node_agent", "0.0.1") //TODO expose version configuration
	c.Args = os.Args[1:]
	c.Commands = map[string]cli.CommandFactory{
		"run": func() (cli.Command, error) {
			return &command.RunCommand{}, nil
		},
		"plugin-info": func() (cli.Command, error) {
			return &command.PluginInfoCommand{}, nil
		},
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}
	return exitStatus
}
