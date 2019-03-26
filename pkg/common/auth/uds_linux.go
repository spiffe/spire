// +build linux

package auth

import (
	"syscall"
)

func getPeerPID(fd uintptr) (pid int32, err error) {
	ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return ucred.Pid, nil
}
