//go:build windows
// +build windows

package peertracker

import (
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestWindowsTracker(t *testing.T) {
	testCases := []struct {
		name                string
		pid                 int32
		sc                  *fakeSystemCall
		expectNewWatcherErr string
		expectIsAliveErr    string
		expectLogs          []spiretest.LogEntry
	}{
		{
			name: "success",
			pid:  1000,
			sc: &fakeSystemCall{
				exitCode:  stillActive,
				processID: 1000,
			},
		},
		{
			name:                "idle process",
			pid:                 0,
			expectNewWatcherErr: "caller is the Idle process",
			sc:                  &fakeSystemCall{},
		},
		{
			name:                "system process",
			pid:                 4,
			expectNewWatcherErr: "caller is the System process",
			sc:                  &fakeSystemCall{},
		},
		{
			name:                "process mismatch",
			pid:                 65279,
			expectNewWatcherErr: "process ID does not match with the caller",
			sc: &fakeSystemCall{
				processID: 65276,
			},
		},
		{
			name: "compare object handle not found",
			pid:  65279,
			sc: &fakeSystemCall{
				processID:                      65279,
				exitCode:                       stillActive,
				isCompareObjectHandlesNotFound: true,
			},
		},
		{
			name:                "get process id error",
			pid:                 1000,
			expectNewWatcherErr: "error getting process id from handle: get process id error",
			sc: &fakeSystemCall{
				processID:       1000,
				getProcessIDErr: errors.New("get process id error"),
			},
		},
		{
			name: "invalid handle",
			pid:  1000,
			sc: &fakeSystemCall{
				processID: 1000,
				handle:    windows.InvalidHandle,
			},
			expectIsAliveErr: "caller is no longer being watched",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Caller is no longer being watched",
					Data: logrus.Fields{
						telemetry.PID: "1000",
					},
				},
			},
		},
		{
			name: "get exit code process error",
			pid:  1000,
			sc: &fakeSystemCall{
				exitCode:              stillActive,
				getExitCodeProcessErr: errors.New("get exit code process error"),
				processID:             1000,
			},
			expectIsAliveErr: "error getting exit code from the process: get exit code process error",
		},
		{
			name: "process not active",
			pid:  1000,
			sc: &fakeSystemCall{
				exitCode:  100,
				processID: 1000,
			},
			expectIsAliveErr: "caller exit detected: exit code: 100",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Caller is not running anymore",
					Data: logrus.Fields{
						logrus.ErrorKey: "caller exit detected: exit code: 100",
						telemetry.PID:   "1000",
					},
				},
			},
		},
		{
			name: "compare object handles error",
			pid:  1000,
			sc: &fakeSystemCall{
				compareObjectHandlesErr: errors.New("compare object handles error"),
				exitCode:                stillActive,
				processID:               1000,
			},
			expectIsAliveErr: "current process handle does not refer to the same original process: CompareObjectHandles failed: compare object handles error",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Current process handle does not refer to the same original process: CompareObjectHandles failed",
					Data: logrus.Fields{
						logrus.ErrorKey: "compare object handles error",
						telemetry.PID:   "1000",
					},
				},
			},
		},
		{
			name: "close handle error",
			pid:  1000,
			sc: &fakeSystemCall{
				closeHandleErr: errors.New("close handle error"),
				exitCode:       stillActive,
				processID:      1000,
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Could not close process handle in liveness check",
					Data: logrus.Fields{
						logrus.ErrorKey: "close handle error",
						telemetry.PID:   "1000",
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			log, logHook := logtest.NewNullLogger()
			tracker := &windowsTracker{
				log: log,
				sc:  testCase.sc,
			}
			tracker.sc = testCase.sc

			// Exercise NewWatcher
			w, err := tracker.NewWatcher(CallerInfo{PID: testCase.pid})
			if testCase.expectNewWatcherErr != "" {
				require.Nil(t, w)
				require.EqualError(t, err, testCase.expectNewWatcherErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, w)

			// Exercise IsAlive
			err = w.IsAlive()
			if testCase.expectIsAliveErr != "" {
				require.EqualError(t, err, testCase.expectIsAliveErr)
				spiretest.AssertLogs(t, logHook.AllEntries(), testCase.expectLogs)
				return
			}
			require.NoError(t, err)
			spiretest.AssertLogs(t, logHook.AllEntries(), testCase.expectLogs)
		})
	}
}

type fakeSystemCall struct {
	handle    windows.Handle
	exitCode  uint32
	processID uint32

	closeHandleErr                 error
	compareObjectHandlesErr        error
	getExitCodeProcessErr          error
	getProcessIDErr                error
	openProcessErr                 error
	isCompareObjectHandlesNotFound bool
}

func (s *fakeSystemCall) CloseHandle(h windows.Handle) error {
	return s.closeHandleErr
}

func (s *fakeSystemCall) CompareObjectHandles(h1, h2 windows.Handle) error {
	return s.compareObjectHandlesErr
}

func (s *fakeSystemCall) GetExitCodeProcess(h windows.Handle, exitCode *uint32) error {
	*exitCode = s.exitCode
	return s.getExitCodeProcessErr
}

func (s *fakeSystemCall) GetProcessID(h windows.Handle) (uint32, error) {
	return s.processID, s.getProcessIDErr
}

func (s *fakeSystemCall) OpenProcess(pid int32) (handle windows.Handle, err error) {
	return s.handle, s.openProcessErr
}

func (s *fakeSystemCall) IsCompareObjectHandlesFound() bool {
	return !s.isCompareObjectHandlesNotFound
}
