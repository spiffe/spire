package main

import (
	"os"

	"github.com/spiffe/spire/cmd/spire-agent/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
