package control_plane_cli

import (
	"log"
	"os"

	"github.com/mitchellh/cli"
	"github.com/spiffe/sri/cmd/spire-server/cli/command"
)

func Run(args []string) int {

	c := cli.NewCLI("spire-server", "0.0.1") //TODO expose version configuration
	c.Args = os.Args[1:]
	c.Commands = map[string]cli.CommandFactory{
		"start": func() (cli.Command, error) {
			return &command.StartCommand{}, nil
		},
		"stop": func() (cli.Command, error) {
			return &command.StopCommand{}, nil
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
