package main

import "github.com/spiffe/sri/control_plane/cli"
import "os"

func main() {
	control_plane_cli.Run(os.Args)
}
