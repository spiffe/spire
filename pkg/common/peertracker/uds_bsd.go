// +build darwin freebsd netbsd openbsd

package peertracker

import (
	"fmt"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/unix"
)

func getCallerInfo(fd uintptr) (CallerInfo, error) {
	result, err := unix.GetsockoptInt(int(fd), 0, 0x002) // getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID)
	if err != nil {
		return CallerInfo{}, err
	}

	p, err := process.NewProcess(int32(result))
	if err != nil {
		return CallerInfo{}, err
	}

	uID, err := getUID(p)
	if err != nil {
		return CallerInfo{}, err
	}

	gID, err := getGID(p)
	if err != nil {
		return CallerInfo{}, err
	}

	// Addr expected to fail on k8s when "hostPID" is not provided
	addr, _ := getAddr(p)

	info := CallerInfo{
		PID:        int32(result),
		UID:        uint32(uID),
		GID:        uint32(gID),
		BinaryAddr: addr,
	}

	return info, nil
}

func getUID(proc *process.Process) (int32, error) {
	uids, err := proc.Uids()
	if err != nil {
		return 0, fmt.Errorf("failed UIDs lookup: %v", err)
	}

	switch len(uids) {
	case 0:
		return 0, fmt.Errorf("failed UIDs lookup: no UIDs for process")
	case 1:
		return uids[0], nil
	default:
		return uids[1], nil
	}
}

func getGID(proc *process.Process) (int32, error) {
	gids, err := proc.Gids()
	if err != nil {
		return 0, fmt.Errorf("failed GIDs lookup: %v", err)
	}

	switch len(gids) {
	case 0:
		return 0, fmt.Errorf("failed GIDs lookup: no GIDs for process")
	case 1:
		return gids[0], nil
	default:
		return gids[1], nil
	}
}

func getAddr(proc *process.Process) (string, error) {
	path, err := proc.Exe()
	if err != nil {
		return "", fmt.Errorf("failed path lookup: %v", err)
	}

	return path, nil
}
