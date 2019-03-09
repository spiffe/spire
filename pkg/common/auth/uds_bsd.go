// +build darwin freebsd netbsd openbsd

package auth

import (
	"golang.org/x/sys/unix"
)

func getPeerPID(fd uintptr) (pid int32, err error) {
	result, err := unix.GetsockoptInt(int(fd), 0, 0x002) //getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID)
	if err != nil {
		return 0, err
	}
	return int32(result), nil
}
