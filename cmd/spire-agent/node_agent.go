package main

import (
	"github.com/spiffe/sri/cmd/spire-agent/cli"
	"os"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
