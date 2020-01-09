package main

import (
	"os"

	"github.com/spiffe/spire/cmd/spire-server/cli"
)

func main() {
	os.Exit(new(cli.CLI).Run(os.Args[1:]))
}
