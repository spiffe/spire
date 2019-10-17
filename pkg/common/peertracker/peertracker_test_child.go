// +build ignore

// This file is used during testing. It is built as an external binary
// and called from the test suite in order to exercise various peer
// tracking scenarios
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
)

func main() {
	var socketPath string
	flag.StringVar(&socketPath, "socketPath", "", "path to peertracker socket")
	flag.Parse()

	// We are a grandchild - send a sign then sleep forever
	if socketPath == "" {
		fmt.Fprintf(os.Stdout, "i'm alive!")

		select {}
	}

	if socketPath == "" {
		fmt.Fprint(os.Stderr, "-socketPath or noop flag required")
		os.Exit(4)
	}

	addr := &net.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	}

	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to socket: %v", err)
		os.Exit(5)
	}

	fd, err := conn.File()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get socket descriptor: %v", err)
		os.Exit(6)
	}

	// Pass our fork the socket's file descriptor
	procattr := &syscall.ProcAttr{
		Files: []uintptr{
			os.Stdin.Fd(),
			fd.Fd(),
		},
	}

	pid, err := syscall.ForkExec(os.Args[0], []string{os.Args[0]}, procattr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to produce grandchild: %v", err)
		os.Exit(7)
	}

	// Inform our caller of the grandchild pid
	fmt.Fprintf(os.Stdout, "%v", pid)
	os.Exit(0)
}
