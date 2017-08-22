package main

import (
	"github.com/spiffe/sri/node_agent/cli"
	"os"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
