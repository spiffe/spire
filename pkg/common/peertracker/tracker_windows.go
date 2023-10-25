//go:build windows

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
	stillActive = 259 // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
)

type windowsTracker struct {
	log logrus.FieldLogger
	sc  systemCaller
}

func newTracker(log logrus.FieldLogger) (*windowsTracker, error) {
	return &windowsTracker{
		log: log.WithField(telemetry.Type, windowsType),
		sc:  &systemCall{},
	}, nil
}

func (t *windowsTracker) NewWatcher(info CallerInfo) (Watcher, error) {
	ww, err := t.newWindowsWatcher(info, t.log)
	if err != nil {
		return nil, err
	}
	return ww, nil
}

func (*windowsTracker) Close() {
}

type windowsWatcher struct {
	mtx        sync.Mutex
	procHandle windows.Handle

	pid int32
	log logrus.FieldLogger

	sc systemCaller
}

func (t *windowsTracker) newWindowsWatcher(info CallerInfo, log logrus.FieldLogger) (*windowsWatcher, error) {
	// Having an open process handle prevents the process object from being destroyed,
	// keeping the process ID valid, so this is the first thing that we do.
	procHandle, err := t.sc.OpenProcess(info.PID)
	if err != nil {
		return nil, err
	}

	// Find out if the PID is a well known PID that we don't
	// expect from a workload.
	switch info.PID {
	case 0:
		// Process ID 0 is the Idle process
		return nil, errors.New("caller is the Idle process")
	case 4:
		// Process ID 4 is the System process
		return nil, errors.New("caller is the System process")
	}

	// This is a mitigation for attacks that leverage opening a
	// named pipe through the local SMB server that set the PID
	// attribute to 0xFEFF (65279). We wanto to prevent abusing
	// the fact that Windows reuses PID values and an attacker could
	// cycle through process creation until it has a suitable process
	// meeting the security check requirements from SMB server.
	// Note that 65279 is not a valid PID in Windows because is not
	// a multiple of 4, but if the SMB server calls OpenProcess on
	// 65279 it will round down and open the PID 65276 which could
	// be created by the attacker.
	// This check makes sure that the process handle obtained from
	// the PID discovered through the GetNamedPipeClientProcessId
	// call matches the one that is obtained from that process ID.
	pid, err := t.sc.GetProcessID(procHandle)
	if err != nil {
		return nil, fmt.Errorf("error getting process id from handle: %w", err)
	}
	if int32(pid) != info.PID {
		return nil, errors.New("process ID does not match with the caller")
	}

	log = log.WithFields(logrus.Fields{
		telemetry.PID: info.PID,
	})

	return &windowsWatcher{
		log:        log,
		pid:        info.PID,
		procHandle: procHandle,
		sc:         t.sc,
	}, nil
}

func (w *windowsWatcher) Close() {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	if err := w.sc.CloseHandle(w.procHandle); err != nil {
		w.log.WithError(err).Warn("Could not close process handle")
	}
	w.procHandle = windows.InvalidHandle
}

func (w *windowsWatcher) IsAlive() error {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	if w.procHandle == windows.InvalidHandle {
		w.log.Warn("Caller is no longer being watched")
		return errors.New("caller is no longer being watched")
	}

	// The process object remains as long as the process is still running or
	// as long as there is a handle to the process object.
	// GetExitCodeProcess can be called to retrieve the exit code.
	var exitCode uint32
	err := w.sc.GetExitCodeProcess(w.procHandle, &exitCode)
	if err != nil {
		return fmt.Errorf("error getting exit code from the process: %w", err)
	}
	if exitCode != stillActive {
		err = fmt.Errorf("caller exit detected: exit code: %d", exitCode)
		w.log.WithError(err).Warnf("Caller is not running anymore")
		return err
	}

	h, err := w.sc.OpenProcess(w.pid)
	if err != nil {
		w.log.WithError(err).Warn("Caller exit suspected due to failure to open process")
		return fmt.Errorf("caller exit suspected due to failure to open process: %w", err)
	}
	defer func() {
		if err := w.sc.CloseHandle(h); err != nil {
			w.log.WithError(err).Warn("Could not close process handle in liveness check")
		}
	}()

	if w.sc.IsCompareObjectHandlesFound() {
		if err := w.sc.CompareObjectHandles(w.procHandle, h); err != nil {
			w.log.WithError(err).Warn("Current process handle does not refer to the same original process: CompareObjectHandles failed")
			return fmt.Errorf("current process handle does not refer to the same original process: CompareObjectHandles failed: %w", err)
		}
	}

	return nil
}

func (w *windowsWatcher) PID() int32 {
	return w.pid
}

type systemCaller interface {
	// CloseHandle closes an open object handle.
	CloseHandle(windows.Handle) error

	// CompareObjectHandles compares two object handles to determine if they
	// refer to the same underlying kernel object
	CompareObjectHandles(windows.Handle, windows.Handle) error

	// OpenProcess returns an open handle to the specified process id.
	OpenProcess(int32) (windows.Handle, error)

	// GetProcessID retrieves the process identifier corresponding
	// to the specified process handle.
	GetProcessID(windows.Handle) (uint32, error)

	// GetExitCodeProcess retrieves the termination status of the
	// specified process handle.
	GetExitCodeProcess(windows.Handle, *uint32) error

	// IsCompareObjectHandlesFound returns true if the CompareObjectHandles
	// function could be found in this Windows instance
	IsCompareObjectHandlesFound() bool
}

type systemCall struct {
}

func (s *systemCall) CloseHandle(h windows.Handle) error {
	return windows.CloseHandle(h)
}

func (s *systemCall) IsCompareObjectHandlesFound() bool {
	return isCompareObjectHandlesFound()
}

func (s *systemCall) CompareObjectHandles(h1, h2 windows.Handle) error {
	return compareObjectHandles(h1, h2)
}

func (s *systemCall) GetExitCodeProcess(h windows.Handle, exitCode *uint32) error {
	return windows.GetExitCodeProcess(h, exitCode)
}

func (s *systemCall) GetProcessID(h windows.Handle) (uint32, error) {
	return windows.GetProcessId(h)
}

func (s *systemCall) OpenProcess(pid int32) (handle windows.Handle, err error) {
	return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
}
