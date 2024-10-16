package main

import (
	"os"

	"github.com/spiffe/spire/cmd/spire-server/cli"
	"github.com/spiffe/spire/pkg/common/entrypoint"
)

func main() {
	os.Exit(entrypoint.NewEntryPoint(new(cli.CLI).Run).Main())
}
