package main

import (
	"os"

	cli "github.com/spiffe/sri/node_agent/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
