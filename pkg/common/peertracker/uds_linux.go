// +build linux

package peertracker

import (
	"syscall"
)

func getCallerInfo(fd uintptr) (CallerInfo, error) {
	ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return CallerInfo{}, err
	}

	info := CallerInfo{
		PID: ucred.Pid,
		UID: ucred.Uid,
		GID: ucred.Gid,
	}

	return info, nil
}
