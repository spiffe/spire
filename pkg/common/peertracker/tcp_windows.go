//go:build windows
// +build windows

package peertracker

/*
#cgo LDFLAGS: -liphlpapi -lws2_32
#include <getpid.h>
*/
import "C"

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
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

	pid := C.getOwningPIDFromLocalConn(C.int(callerAddr.Port), C.int(agentAddr.Port))
	if pid < 0 {
		return CallerInfo{}, fmt.Errorf("failed to get owning PID. Return code is: %d", pid)
	}

	return CallerInfo{
		Addr: conn.RemoteAddr(),
		PID:  int32(pid),
	}, nil
}

func compareObjectHandles(firstHandle, secondHandle windows.Handle) (err error) {
	modkernel32 := windows.NewLazySystemDLL("kernelbase.dll")
	procCompareObjectHandles := modkernel32.NewProc("CompareObjectHandles")

	r1, _, e1 := syscall.Syscall(procCompareObjectHandles.Addr(), 2, uintptr(firstHandle), uintptr(secondHandle), 0)
	if r1 == 0 {
		err = syscall.Errno(e1)
	}
	return err
}
