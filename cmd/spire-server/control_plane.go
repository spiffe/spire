package main

import (
	"os"

	"github.com/spiffe/sri/cmd/spire-server/cli"
)

func main() {
	control_plane_cli.Run(os.Args)
}
