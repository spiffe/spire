//go:build ignore
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
	var tcpSocketPort int
	flag.IntVar(&tcpSocketPort, "tcpSocketPort", 0, "port to peertracker tcp socket")
	flag.Parse()

	// We are a grandchild - send a sign then sleep forever
	if tcpSocketPort == 0 {
		fmt.Fprintf(os.Stdout, "i'm alive!")
		select {}
	}

	if tcpSocketPort == 0 {
		fmt.Fprint(os.Stderr, "-tcpSocketPort or noop flag required")
		os.Exit(4)
	}

	addr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: tcpSocketPort,
	}

	_, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to socket: %v", err)
		os.Exit(5)
	}

	procattr := &syscall.ProcAttr{
		Env:   os.Environ(),
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
	}
	pid, _, err := syscall.StartProcess(os.Args[0], []string{os.Args[0]}, procattr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to produce grandchild: %v", err)
		os.Exit(7)
	}

	// Inform our caller of the grandchild pid
	fmt.Fprintf(os.Stdout, "%v", pid)
	os.Exit(0)
}
