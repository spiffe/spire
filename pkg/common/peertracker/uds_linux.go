//go:build linux

package peertracker

import (
	"golang.org/x/sys/unix"
)

func getCallerInfoFromFileDescriptor(fd uintptr) (CallerInfo, error) {
	ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
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
