//go:build windows

package peertracker

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernelbase = windows.NewLazyDLL("kernelbase.dll")
	kernel32   = windows.NewLazyDLL("kernel32.dll")

	procCompareObjectHandles           = kernelbase.NewProc("CompareObjectHandles")
	procCompareObjectHandlesErr        = procCompareObjectHandles.Find()
	procGetNamedPipeClientProcessID    = kernel32.NewProc("GetNamedPipeClientProcessId")
	procGetNamedPipeClientProcessIDErr = procGetNamedPipeClientProcessID.Find()
)

func getCallerInfoFromNamedPipeConn(conn net.Conn) (CallerInfo, error) {
	var info CallerInfo

	type Fder interface {
		Fd() uintptr
	}
	fder, ok := conn.(Fder)
	if !ok {
		conn.Close()
		return info, errors.New("invalid connection")
	}

	var pid int32
	if err := getNamedPipeClientProcessID(windows.Handle(fder.Fd()), &pid); err != nil {
		return info, fmt.Errorf("error in GetNamedPipeClientProcessId function: %w", err)
	}

	return CallerInfo{
		Addr: conn.RemoteAddr(),
		PID:  pid,
	}, nil
}

// getNamedPipeClientProcessID retrieves the client process identifier
// for the specified handle representing a named pipe.
func getNamedPipeClientProcessID(pipe windows.Handle, clientProcessID *int32) (err error) {
	if procGetNamedPipeClientProcessIDErr != nil {
		return procGetNamedPipeClientProcessIDErr
	}
	r1, _, e1 := syscall.SyscallN(procGetNamedPipeClientProcessID.Addr(), uintptr(pipe), uintptr(unsafe.Pointer(clientProcessID)))
	if r1 == 0 {
		return e1
	}
	return nil
}

func isCompareObjectHandlesFound() bool {
	return procCompareObjectHandlesErr == nil
}

// compareObjectHandles compares two object handles to determine if they
// refer to the same underlying kernel object
func compareObjectHandles(firstHandle, secondHandle windows.Handle) error {
	if isCompareObjectHandlesFound() {
		return procCompareObjectHandlesErr
	}
	r1, _, e1 := syscall.SyscallN(procCompareObjectHandles.Addr(), uintptr(firstHandle), uintptr(secondHandle))
	if r1 == 0 {
		return e1
	}
	return nil
}
