package main

import (
	"os"

	"github.com/spiffe/spire/cmd/spire-server/cli"
	"log"
	"net/http"
	_ "net/http/pprof"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	os.Exit(cli.Run(os.Args[1:]))

}
