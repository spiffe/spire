// +build linux

package peertracker

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
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
	return
}

type linuxWatcher struct {
	gid       uint32
	pid       int32
	procfh    *os.File
	starttime string
	uid       uint32
}

func newLinuxWatcher(info CallerInfo) (*linuxWatcher, error) {
	// If PID == 0, something is wrong...
	if info.PID == 0 {
		return nil, errors.New("could not resolve caller information")
	}

	// Grab a handle to proc first since that's the fastest thing we can do
	procfh, err := os.Open(fmt.Sprintf("/proc/%v", info.PID))
	if err != nil {
		return nil, fmt.Errorf("could not open caller's proc directory: %v", err)
	}

	starttime, err := getStarttime(info.PID)
	if err != nil {
		return nil, err
	}

	return &linuxWatcher{
		gid:       info.GID,
		pid:       info.PID,
		procfh:    procfh,
		starttime: starttime,
		uid:       info.UID,
	}, nil
}

func (l *linuxWatcher) Close() {
	l.procfh.Close()
	l.procfh = nil
}

func (l *linuxWatcher) IsAlive() error {
	if l.procfh == nil {
		return errors.New("caller is no longer being watched")
	}

	// First we will check if we can read from the original directory handle. If the
	// process has exited since we opened it, the read should fail.
	_, err := l.procfh.Readdir(1)
	if err != nil {
		return errors.New("caller exit suspected due to failed proc read")
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
		return errors.New("caller exit suspected due to failed proc read")
	}
	if currentStarttime != l.starttime {
		return errors.New("new process detected: starttime mismatch")
	}

	// Finally, read the UID and GID off the proc directory to determine the owner. If
	// we got beaten by a PID race when opening the proc handle originally, we can at
	// least get to know that the race winner is running as the same user and group as
	// the original caller by comparing it to the received CallerInfo.
	info, err := l.procfh.Stat()
	if err != nil {
		return errors.New("caller exit suspected due to failed proc read")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("failed to read proc ownership info: is this a supported system?")
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

func getStarttime(pid int32) (string, error) {
	statfd, err := os.Open(fmt.Sprintf("/proc/%v/stat", pid))
	if err != nil {
		return "", fmt.Errorf("could not open caller stats: %v", err)
	}

	statBytes, err := ioutil.ReadAll(statfd)
	if err != nil {
		return "", fmt.Errorf("could not read caller stats: %v", err)
	}

	// starttime is the 22nd field in the proc stat data
	// Field number 38 was introduced in Linux 2.1.22
	// Protect against invalid index and reject anything before 2.1.22
	statStrings := strings.Split(string(statBytes), " ")
	if len(statStrings) < 38 {
		return "", errors.New("bad stat data or unsupported platform")
	}

	return statStrings[21], nil
}
