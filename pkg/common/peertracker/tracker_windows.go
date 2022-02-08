//go:build windows
// +build windows

package peertracker

import (
	"errors"
	"fmt"
	"sync"

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
	log        logrus.FieldLogger
}

func newWindowsWatcher(info CallerInfo, log logrus.FieldLogger) (*windowsWatcher, error) {
	// Having an open process handle prevents the process object from being destroyed,
	// keeping the process ID valid, so this is the first thing that we do.
	procHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(info.PID))
	if err != nil {
		return nil, err
	}

	log = log.WithFields(logrus.Fields{
		telemetry.PID: info.PID,
	})

	return &windowsWatcher{
		pid:        info.PID,
		procHandle: procHandle,
		log:        log,
	}, nil
}

func (l *windowsWatcher) Close() {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if err := windows.CloseHandle(l.procHandle); err != nil {
		l.log.WithError(err).Warn("Could not close process handle")
	}
	l.procHandle = windows.InvalidHandle
}

func (l *windowsWatcher) IsAlive() error {
	l.mtx.Lock()
	defer l.mtx.Unlock()

	if l.procHandle == windows.InvalidHandle {
		l.log.Warn("Caller is no longer being watched")
		return errors.New("caller is no longer being watched")
	}

	const stillActive = 259 // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
	var exitCode uint32
	err := windows.GetExitCodeProcess(l.procHandle, &exitCode)
	if err != nil {
		return err
	}
	if exitCode != stillActive {
		l.log.WithError(err).Warnf("Caller is not running anymore: exit code: %d", exitCode)
		return fmt.Errorf("caller is not running anymore: exit code: %d", exitCode)
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(l.pid))
	if err != nil {
		l.log.WithError(err).Warn("Caller exit suspected due to failure to open process")
		return fmt.Errorf("caller exit suspected due to failure to open process: %w", err)
	}
	defer func() {
		if err := windows.CloseHandle(h); err != nil {
			l.log.WithError(err).Warn("Could not close process handle in liveness check")
		}
	}()

	err = compareObjectHandles(l.procHandle, h)
	if err != nil {
		l.log.WithError(err).Warn("Current process handle does not refer to the same original process: CompareObjectHandles failed")
		return fmt.Errorf("current process handle does not refer to the same original process: CompareObjectHandles failed: %w", err)
	}

	return nil
}

func (l *windowsWatcher) PID() int32 {
	return l.pid
}
