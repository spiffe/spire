//go:build ignore
// +build ignore

// This file is used during testing. It is built as an external binary
// and called from the test suite in order to exercise various peer
// tracking scenarios
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWs2_32 = windows.NewLazySystemDLL("ws2_32.dll")

	// WSADuplicateSocketA function (winsock2.h)
	procWSADuplicateSocketA = modWs2_32.NewProc("WSADuplicateSocketA")
)

func main() {
	var (
		tcpSocketPort    int
		protocolInfoFile string
	)

	flag.IntVar(&tcpSocketPort, "tcpSocketPort", -1, "port to peertracker tcp socket")
	flag.StringVar(&protocolInfoFile, "protocolInfoFile", "", "path to file containing WSAPROTOCOL_INFO structure")
	flag.Parse()

	if protocolInfoFile == "" {
		fmt.Fprint(os.Stderr, "-protocolInfoFile flag is required")
		os.Exit(1)
	}

	// We are a grandchild - send a sign then sleep forever
	if tcpSocketPort == -1 {
		piBytes, err := getProtocolInfo(protocolInfoFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file with WSAPROTOCOL_INFO structure: %v", err)
			os.Exit(2)
		}

		pi := (*windows.WSAProtocolInfo)(unsafe.Pointer(&piBytes[0]))
		fd, err := windows.WSASocket(-1, -1, -1, pi, 0, 0)

		if err != nil {
			fmt.Fprintf(os.Stderr, "WSASocket error: %v", err)
			os.Exit(3)
		}

		err = send(fd, "i'm alive!")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Send failed: %v", err)
			os.Exit(4)
		}

		// sleep forever
		select {}
	}

	addr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: tcpSocketPort,
	}

	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DialTCP failed: %v", err)
		os.Exit(5)
	}

	procattr := &syscall.ProcAttr{
		Env:   os.Environ(),
		Files: []uintptr{0, 0, 0}, // Do not block on stdin / stdout / stderr
	}

	pid, _, err := syscall.StartProcess(os.Args[0], []string{os.Args[0], "-protocolInfoFile", protocolInfoFile}, procattr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to produce grandchild: %v", err)
		os.Exit(7)
	}

	if err := duplicateSocket(conn, pid, protocolInfoFile); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to duplicate socket: %v", err)
		os.Exit(8)
	}

	// Inform our caller of the grandchild pid
	fmt.Fprintf(os.Stdout, "%v", pid)
	os.Exit(0)
}

// wsaDuplicateSocket calls the WSADuplicateSocket function that returns
// a WSAPROTOCOL_INFO structure that can be used to create a new socket
// descriptor for a shared socket
func wsaDuplicateSocket(socket windows.Handle, processID uint32, protocolInfo *windows.WSAProtocolInfo) (err error) {
	r1, _, e1 := syscall.Syscall(procWSADuplicateSocketA.Addr(), 3, uintptr(socket), uintptr(processID), uintptr(unsafe.Pointer(protocolInfo)))
	if r1 == 0xffffffff {
		return e1
	}
	return nil
}

// getProtocolInfo gets the WSAPROTOCOL_INFO structure from
// the file at protocolInfoFile path. If there is no content
// after 15 seconds, this function times out
func getProtocolInfo(protocolInfoFile string) (piBytes []byte, err error) {
	timeout := time.After(15 * time.Second)
	tick := time.Tick(500 * time.Millisecond)

	for {
		select {
		case <-timeout:
			return []byte{}, errors.New("timed out")
		case <-tick:
			piBytes, _ = os.ReadFile(protocolInfoFile)
			if len(piBytes) > 0 {
				return piBytes, nil
			}
		}
	}
}

// send sends data on a connected socket
func send(socket windows.Handle, data string) (err error) {
	var (
		bufs       windows.WSABuf
		overlapped windows.Overlapped
		bufcnt     uint32
	)

	bufs.Len = uint32(len(data))
	bufs.Buf, err = windows.BytePtrFromString(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "BytePtrFromString failed: %v", err)
		os.Exit(2)
	}

	return windows.WSASend(socket, &bufs, 1, &bufcnt, 0, &overlapped, nil)
}

// duplicateSocket calls the WSADuplicateSocket function for the specified
// connection and process ID, storing the resulting WSAPROTOCOL_INFO
// structure in protocolInfoFile. Calling WSADuplicateSocket is needed
// to enable socket sharing across processes.
// https://docs.microsoft.com/en-us/windows/win32/winsock/shared-sockets-2
func duplicateSocket(conn *net.TCPConn, pid int, protocolInfoFile string) error {
	if conn == nil {
		return errors.New("no connection")
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw network connection: %v", err)
	}

	b := make([]byte, int(unsafe.Sizeof(windows.WSAProtocolInfo{})))
	ctrlErr := rawConn.Control(func(fd uintptr) {
		err = wsaDuplicateSocket(windows.Handle(fd), uint32(pid), (*windows.WSAProtocolInfo)(unsafe.Pointer(&b[0])))
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	if err != nil {
		return fmt.Errorf("error in WSADuplicateSocket: %v", err)
	}
	if err := os.WriteFile(protocolInfoFile, b, 0644); err != nil {
		return fmt.Errorf("writing wsaprotocolinfo file failed: %v", err)
	}

	return nil
}
