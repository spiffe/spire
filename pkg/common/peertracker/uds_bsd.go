//go:build darwin || freebsd || netbsd || openbsd

package peertracker

import (
	"fmt"

	"github.com/spiffe/spire/pkg/common/util"
	"golang.org/x/sys/unix"
)

func getCallerInfoFromFileDescriptor(fd uintptr) (CallerInfo, error) {
	result, err := unix.GetsockoptInt(int(fd), 0, 0x002) // getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID)
	if err != nil {
		return CallerInfo{}, fmt.Errorf("failed to get PID from file descriptor: %w", err)
	}

	pidInt32, err := util.CheckedCast[int32](result)
	if err != nil {
		return CallerInfo{}, fmt.Errorf("failed to cast PID from file descriptor: %w", err)
	}

	info := CallerInfo{
		PID: pidInt32,
	}

	return info, nil
}
