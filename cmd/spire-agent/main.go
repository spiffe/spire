package main

import (
	"os"

	"github.com/spiffe/spire/cmd/spire-agent/cli"
	"github.com/spiffe/spire/pkg/common/entrypoint"
)

func main() {
	os.Setenv("$", "$") // Allow escaping $ in config files using ExpandEnv
	os.Exit(entrypoint.NewEntryPoint(new(cli.CLI).Run).Main())
}
