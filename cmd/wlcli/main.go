package main

import (
	"os"

	"github.com/spiffe/spire/cmd/wlcli/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
