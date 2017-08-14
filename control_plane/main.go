package main

import (
	"os"

	"github.com/spiffe/control-plane/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
