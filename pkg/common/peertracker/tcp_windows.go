//go:build windows
// +build windows

package peertracker

/*
#cgo LDFLAGS: -liphlpapi -lws2_32
#include <getpid_windows.h>
*/
import "C"

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	modKernelbase = windows.NewLazySystemDLL("kernelbase.dll")

	// CompareObjectHandles function (handleapi.h)
	procCompareObjectHandles = modKernelbase.NewProc("CompareObjectHandles")
)

func getCallerInfoFromTCPConn(conn net.Conn) (CallerInfo, error) {
	agentAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return CallerInfo{}, ErrInvalidConnection
	}

	callerAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return CallerInfo{}, ErrInvalidConnection
	}

	var pid C.int
	r1 := C.getOwningPIDFromLocalConn(C.int(callerAddr.Port), C.int(agentAddr.Port), &pid)
	if r1 != windows.NO_ERROR {
		return CallerInfo{}, fmt.Errorf("failed to get owning PID: %w", syscall.Errno(r1))
	}

	return CallerInfo{
		Addr: conn.RemoteAddr(),
		PID:  int32(pid),
	}, nil
}

// compareObjectHandles compares two object handles to determine if they
// refer to the same underlying kernel object
func compareObjectHandles(firstHandle, secondHandle windows.Handle) error {
	r1, _, e1 := syscall.Syscall(procCompareObjectHandles.Addr(), 2, uintptr(firstHandle), uintptr(secondHandle), 0)
	if r1 == 0 {
		return e1
	}
	return nil
}
