package main

import (
	"log"
	"os"

	"github.com/mitchellh/cli"
)

const (
	serverAddr           = "localhost:8081"
	parentSpiffeIDPrefix = "spiffe://example.org/spire/agent/join_token/"
	spiffeIDPrefix       = "spiffe://example.org/"
	workloadPath         = "/go/src/github.com/spiffe/spire/functional/tools/workload/workload"
)

func main() {
	if _, err := os.Stat(workloadPath); os.IsNotExist(err) {
		panic("Do not run this tool outside the Docker container")
	}

	c := cli.NewCLI("stresstest", "0.0.1") //TODO expose version configuration
	c.Args = os.Args[1:]
	c.Commands = map[string]cli.CommandFactory{
		"run": func() (cli.Command, error) {
			return &Run{}, nil
		},
		"createusers": func() (cli.Command, error) {
			return &CreateUsers{}, nil
		},
	}

	_, err := c.Run()
	if err != nil {
		log.Println(err)
	}

}
