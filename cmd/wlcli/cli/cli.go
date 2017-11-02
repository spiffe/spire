package cli

import (
	"log"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/wlcli/cli/command"
)

func Run(args []string) int {
	c := cli.NewCLI("wl-client", "0.0.1")
	c.Args = args

	c.Commands = map[string]cli.CommandFactory{
		"fetchsvid": func() (cli.Command, error) {
			return &command.FetchSvid{}, nil
		},
	}
	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}
	return exitStatus
}
