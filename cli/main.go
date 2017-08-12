package cli

import (
	"log"
	"os"

	"github.com/mitchellh/cli"
	"github.com/spiffe/control-plane/cli/command"
)

func Run(args []string) int {

	c := cli.NewCLI("control-plane", "0.0.1") //TODO expose version configuration
	c.Args = os.Args[1:]
	c.Commands = map[string]cli.CommandFactory{
		"server": func() (cli.Command, error) {
			return &command.ServerCommand{}, nil
		},
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}
	return exitStatus
}
