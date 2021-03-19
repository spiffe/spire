// +build linux

package peertracker

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"syscall"
)

type linuxTracker struct{}

func newTracker() (linuxTracker, error) {
	return linuxTracker{}, nil
}

func (linuxTracker) NewWatcher(info CallerInfo) (Watcher, error) {
	return newLinuxWatcher(info)
}

func (linuxTracker) Close() {
}

type linuxWatcher struct {
	gid       uint32
	pid       int32
	mtx       sync.Mutex
	procPath  string
	procfd    int
	starttime string
	uid       uint32
}

func newLinuxWatcher(info CallerInfo) (*linuxWatcher, error) {
	// If PID == 0, something is wrong...
	if info.PID == 0 {
		return nil, errors.New("could not resolve caller information")
	}

	procPath := fmt.Sprintf("/proc/%v", info.PID)

	// Grab a handle to proc first since that's the fastest thing we can do
	procfd, err := syscall.Open(procPath, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("could not open caller's proc directory: %v", err)
	}

	starttime, err := getStarttime(info.PID)
	if err != nil {
		syscall.Close(procfd)
		return nil, err
	}

	return &linuxWatcher{
		gid:       info.GID,
		pid:       info.PID,
		procPath:  procPath,
		procfd:    procfd,
		starttime: starttime,
		uid:       info.UID,
	}, nil
}

func (l *linuxWatcher) Close() {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if l.procfd < 0 {
		return
	}

	syscall.Close(l.procfd)
	l.procfd = -1
}

func (l *linuxWatcher) IsAlive() error {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if l.procfd < 0 {
		return errors.New("caller is no longer being watched")
	}

	// First we will check if we can read from the original directory handle.
	// If the process has exited since we opened it, the read should fail (i.e.
	// the ReadDirent syscall will return -1)
	var buf [8196]byte
	n, err := syscall.ReadDirent(l.procfd, buf[:])
	if err != nil {
		return fmt.Errorf("caller exit suspected due to failed readdirent: err=%v", err)
	}
	if n < 0 {
		return fmt.Errorf("caller exit suspected due to failed readdirent: n=%d", n)
	}

	// A successful fd read should indicate that the original process is still alive, however
	// it is not clear if the original inode can be freed by Linux while it is still referenced.
	// This _shouldn't_ happen, but if it does, then there might be room for a reused PID to
	// collide with the original inode making the read successful. As an extra measure, ensure
	// that the current `starttime` matches the one we saw originally.
	//
	// This is probably overkill.
	// TODO: Evaluate the use of `starttime` as the primary exit detection mechanism.
	currentStarttime, err := getStarttime(l.pid)
	if err != nil {
		return fmt.Errorf("caller exit suspected due to failure to get starttime: %v", err)
	}
	if currentStarttime != l.starttime {
		return errors.New("new process detected: starttime mismatch")
	}

	// Finally, read the UID and GID off the proc directory to determine the owner. If
	// we got beaten by a PID race when opening the proc handle originally, we can at
	// least get to know that the race winner is running as the same user and group as
	// the original caller by comparing it to the received CallerInfo.
	var stat syscall.Stat_t
	if err := syscall.Stat(l.procPath, &stat); err != nil {
		return fmt.Errorf("caller exit suspected due to failed proc stat: %v", err)
	}
	if stat.Uid != l.uid {
		return fmt.Errorf("new process detected: process uid %v does not match original caller %v", stat.Uid, l.uid)
	}
	if stat.Gid != l.gid {
		return fmt.Errorf("new process detected: process gid %v does not match original caller %v", stat.Gid, l.gid)
	}

	return nil
}

func (l *linuxWatcher) PID() int32 {
	return l.pid
}

func parseTaskStat(stat string) ([]string, error) {
	b := strings.IndexByte(stat, '(')
	e := strings.LastIndexByte(stat, ')')
	if b == -1 || e == -1 {
		return nil, errors.New("task name is not parenthesized")
	}

	fields := make([]string, 0, 52)
	fields = append(fields, strings.Split(stat[:b-1], " ")...)
	fields = append(fields, stat[b+1:e])
	fields = append(fields, strings.Split(stat[e+2:], " ")...)
	return fields, nil
}

func getStarttime(pid int32) (string, error) {
	statBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%v/stat", pid))
	if err != nil {
		return "", fmt.Errorf("could not read caller stat: %v", err)
	}

	statFields, err := parseTaskStat(string(statBytes))
	if err != nil {
		return "", fmt.Errorf("bad stat data: %v", err)
	}

	// starttime is the 22nd field in the proc stat data
	// Field number 38 was introduced in Linux 2.1.22
	// Protect against invalid index and reject anything before 2.1.22
	if len(statFields) < 38 {
		return "", errors.New("bad stat data or unsupported platform")
	}

	return statFields[21], nil
}
