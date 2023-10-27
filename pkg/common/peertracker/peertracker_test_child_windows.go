//go:build ignore

// This file is used during testing. It is built as an external binary
// and called from the test suite in order to exercise various peer
// tracking scenarios
package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/Microsoft/go-winio"
)

func main() {
	var (
		namedPipeName string
	)

	flag.StringVar(&namedPipeName, "namedPipeName", "", "pipe name to peertracker named pipe")
	flag.Parse()

	// We are a grandchild - send a sign then sleep forever
	if namedPipeName == "" {
		fmt.Fprintf(os.Stdout, "i'm alive!")

		select {}
	}

	conn, err := winio.DialPipe(namedPipeName, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DialPipe failed: %v", err)
		os.Exit(5)
	}

	type Fder interface {
		Fd() uintptr
	}
	fder, ok := conn.(Fder)
	if !ok {
		conn.Close()
		fmt.Fprintf(os.Stderr, "invalid connection", err)
		os.Exit(6)
	}

	procattr := &syscall.ProcAttr{
		Env: os.Environ(),
		Files: []uintptr{
			0, // Do not block on stdin
			fder.Fd(),
			0, // Do not block on stderr
		},
	}

	pid, _, err := syscall.StartProcess(os.Args[0], []string{os.Args[0]}, procattr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to produce grandchild: %v", err)
		os.Exit(7)
	}

	// Inform our caller of the grandchild pid
	fmt.Fprintf(os.Stdout, "%v", pid)
	os.Exit(0)
}
