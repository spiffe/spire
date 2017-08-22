package main

import (
	"os"
	
	"github.com/spiffe/sri/node_agent/cli"

)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
