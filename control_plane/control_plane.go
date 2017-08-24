package main

import (
	"os"

	"github.com/spiffe/sri/control_plane/cli"
)

func main() {
	control_plane_cli.Run(os.Args)
}
