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
	var descriptor int
	var socketPath string
	flag.IntVar(&descriptor, "descriptor", 0, "send a bit of data on the fd and then block forever")
	flag.StringVar(&socketPath, "socketPath", "", "path to peertracker socket")
	flag.Parse()

	// We are a grandchild - send a sign then sleep forever
	if descriptor != 0 {
		fd := uintptr(descriptor)
		fh := os.NewFile(fd, "socket")
		if fh == nil {
			fmt.Fprintf(os.Stderr, "could not open descriptor")
			os.Exit(1)
		}

		conn, err := net.FileConn(fh)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not get conn from descriptor: %v", err)
			os.Exit(2)
		}

		theSign := []byte("i'm alive!")
		_, err = conn.Write(theSign)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not write to conn: %v", err)
			os.Exit(3)
		}

		foreverCh := make(chan struct{})
		<-foreverCh
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
			fd.Fd(), // descriptor 1
		},
	}

	pid, err := syscall.ForkExec(os.Args[0], []string{os.Args[0], "-descriptor", "1"}, procattr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to produce grandchild: %v", err)
		os.Exit(7)
	}

	// Inform our caller of the grandchild pid
	fmt.Fprintf(os.Stdout, "%v", pid)
	os.Exit(0)
}
