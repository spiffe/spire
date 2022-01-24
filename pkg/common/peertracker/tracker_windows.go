//go:build windows
// +build windows

package peertracker

import (
	"errors"
	"fmt"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"golang.org/x/sys/windows"
)

const (
	windowsType = "windows"
)

type windowsTracker struct {
	log logrus.FieldLogger
}

func newTracker(log logrus.FieldLogger) (*windowsTracker, error) {
	return &windowsTracker{
		log: log.WithField(telemetry.Type, windowsType),
	}, nil
}

func (l *windowsTracker) NewWatcher(info CallerInfo) (Watcher, error) {
	return newWindowsWatcher(info, l.log)
}

func (*windowsTracker) Close() {
}

type windowsWatcher struct {
	mtx        sync.Mutex
	procHandle windows.Handle
	pid        int32
	uid        string
	gid        string
	startTime  int64 // Nanoseconds since Epoch (00:00:00 UTC, January 1, 1970)
	log        logrus.FieldLogger
}

func newWindowsWatcher(info CallerInfo, log logrus.FieldLogger) (*windowsWatcher, error) {
	// Having an open process handle prevents the process object from being destroyed,
	// keeping the process ID valid, so this is the first thing that we do.
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(info.PID))
	if err != nil {
		return nil, err
	}

	startTime, err := getStartTime(h)
	if err != nil {
		return nil, err
	}

	log = log.WithFields(logrus.Fields{
		telemetry.CallerGID: info.GID,
		telemetry.PID:       info.PID,
		telemetry.CallerUID: info.UID,
		telemetry.StartTime: startTime,
	})

	return &windowsWatcher{
		gid:        info.GID,
		pid:        info.PID,
		procHandle: h,
		startTime:  startTime,
		uid:        info.UID,
		log:        log,
	}, nil
}

func (l *windowsWatcher) Close() {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	syscall.CloseHandle(syscall.Handle(l.procHandle))
	l.procHandle = windows.InvalidHandle
}

func (l *windowsWatcher) IsAlive() error {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if l.procHandle == windows.InvalidHandle {
		l.log.Warn("Caller is no longer being watched")
		return errors.New("caller is no longer being watched")
	}

	const STILL_ACTIVE = 259 // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
	var exitCode uint32
	err := windows.GetExitCodeProcess(l.procHandle, &exitCode)
	if err != nil {
		return err
	}
	if exitCode != STILL_ACTIVE {
		l.log.WithError(err).Warnf("Caller is not running anymore. Exit code is: %d", exitCode)
		return fmt.Errorf("caller is not running anymore. Exit code is: %d", exitCode)
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(l.pid))
	if err != nil {
		l.log.WithError(err).Warn("Caller exit suspected due to failure to open process")
		return fmt.Errorf("caller exit suspected due to failure to open process: %w", err)
	}

	currentStartTime, err := getStartTime(h)
	if err != nil {
		l.log.WithError(err).Warn("Caller exit suspected due to failure to get start time")
		return fmt.Errorf("caller exit suspected due to failure to get start time: %w", err)
	}

	// Compare the start time of the current process with the
	// original process.
	if l.startTime != currentStartTime {
		l.log.WithFields(logrus.Fields{
			telemetry.ExpectStartTime:   l.startTime,
			telemetry.ReceivedStartTime: currentStartTime,
		}).Warn("New process detected: process start time does not match original caller")
		return fmt.Errorf("new process detected: process start time %d does not match original caller %d", currentStartTime, l.startTime)
	}

	// Finally, get the security identifiers to determine the owner. If we got
	// beaten by a PID race when opening the proc handle originally, we can at
	// least get to know that the race winner is running as the same user and
	// group as the original caller by comparing it to the received CallerInfo.
	uid, gid, err := getSIDsFromPID(int(l.pid))
	if err != nil {
		l.log.WithError(err).Warn("Caller exit suspected due to failure to get security identifiers")
		return errors.New("caller exit suspected due to failure to get security identifiers")
	}

	if uid != l.uid {
		l.log.WithFields(logrus.Fields{
			telemetry.ExpectUID:   l.uid,
			telemetry.ReceivedUID: uid,
		}).Warn("New process detected: process uid does not match original caller")
		return fmt.Errorf("new process detected: process uid %q does not match original caller %q", uid, l.uid)
	}
	if gid != l.gid {
		l.log.WithFields(logrus.Fields{
			telemetry.ExpectGID:   l.gid,
			telemetry.ReceivedGID: gid,
		}).Warn("New process detected: process gid does not match original caller")
		return fmt.Errorf("new process detected: process gid %q does not match original caller %q", uid, l.gid)
	}

	return nil
}

func (l *windowsWatcher) PID() int32 {
	return l.pid
}

func getStartTime(procHandle windows.Handle) (int64, error) {
	var CPU windows.Rusage
	if err := windows.GetProcessTimes(procHandle, &CPU.CreationTime, &CPU.ExitTime, &CPU.KernelTime, &CPU.UserTime); err != nil {
		return 0, err
	}

	return CPU.CreationTime.Nanoseconds(), nil
}
