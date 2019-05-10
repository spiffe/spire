// +build darwin freebsd netbsd openbsd

package peertracker

import (
	"golang.org/x/sys/unix"
)

func getCallerInfo(fd uintptr) (CallerInfo, error) {
	result, err := unix.GetsockoptInt(int(fd), 0, 0x002) //getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID)
	if err != nil {
		return CallerInfo{}, err
	}

	info := CallerInfo{
		PID: int32(result),
	}

	return info, nil
}
