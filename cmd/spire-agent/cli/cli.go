package cli

import (
	"log"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-agent/cli/api"
	"github.com/spiffe/spire/cmd/spire-agent/cli/run"
	"github.com/spiffe/spire/pkg/common/version"
)

func Run(args []string) int {
	c := cli.NewCLI("spire-agent", version.Version())
	c.Args = args
	c.Commands = map[string]cli.CommandFactory{
		"api fetch": func() (cli.Command, error) {
			return &api.FetchCLI{}, nil
		},
		"api watch": func() (cli.Command, error) {
			return &api.WatchCLI{}, nil
		},
		"run": func() (cli.Command, error) {
			return &run.RunCLI{}, nil
		},
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}
	return exitStatus
}
