//go:build windows
// +build windows

package entrypoint

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

var runArgs = []string{"process-name", "run"}

type fakeSystemCall struct {
	mtx                 sync.RWMutex
	args                []string
	exitCode            uint32
	isWindowsService    bool
	isWindowsServiceErr error
	runErr              error
	s                   service
	svcSpecificEC       bool
	changeRequestCh     chan svc.ChangeRequest
	statusCh            chan svc.Status
}

func (s *fakeSystemCall) initChannels() {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.changeRequestCh = make(chan svc.ChangeRequest, 1)
	s.statusCh = make(chan svc.Status, 1)
}

func (s *fakeSystemCall) IsWindowsService() (bool, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	return s.isWindowsService, s.isWindowsServiceErr
}

func (s *fakeSystemCall) Run(string, svc.Handler) error {
	var (
		wg            sync.WaitGroup
		svcSpecificEC bool
		exitCode      uint32
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.mtx.RLock()
		defer s.mtx.RUnlock()

		svcSpecificEC, exitCode = s.s.Execute(s.args, s.changeRequestCh, s.statusCh)
	}()

	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
	case <-time.After(time.Minute):
		panic("timed out")
	}

	s.statusCh <- svc.Status{State: svc.Stopped}

	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.svcSpecificEC = svcSpecificEC
	s.exitCode = exitCode
	return s.runErr
}

func newEntryPoint(runCmdFn func(ctx context.Context, args []string) int, sc systemCaller) *EntryPoint {
	return &EntryPoint{
		handler: &service{
			executeServiceFn: func(ctx context.Context, stop context.CancelFunc, args []string) int {
				retCode := runCmdFn(ctx, args[1:])
				defer stop()
				return retCode
			},
		},
		runCmdFn: runCmdFn,
		sc:       sc,
	}
}

func TestNotAService(t *testing.T) {
	tests := []struct {
		name         string
		retCode      int
		expectRunErr string
		sc           *fakeSystemCall
	}{
		{
			name: "success",
			sc:   &fakeSystemCall{},
		},
		{
			name:    "failure",
			retCode: 1,
			sc:      &fakeSystemCall{},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			retCodeCh := make(chan int, 1)

			go func() {
				ep := newEntryPoint(func(ctx context.Context, args []string) int {
					return testCase.retCode
				}, testCase.sc)
				retCodeCh <- ep.Main()
				assert.True(t, true)
			}()

			assertWithTimeout(t, testCase.retCode, retCodeCh)
		})
	}
}

func TestService(t *testing.T) {
	tests := []struct {
		name                  string
		runCmdRetCode         int
		executeServiceFailure bool
		expectRunErr          string
		sc                    *fakeSystemCall
	}{
		{
			name: "success",
			sc: &fakeSystemCall{
				args: runArgs,
				s: service{
					executeServiceFn: func(ctx context.Context, stop context.CancelFunc, args []string) int {
						return 0
					},
				},
				isWindowsService: true,
			},
		},
		{
			name:                  "fatal app exit",
			executeServiceFailure: true,
			sc: &fakeSystemCall{
				args: runArgs,
				s: service{
					executeServiceFn: func(ctx context.Context, stop context.CancelFunc, args []string) int {
						stop()
						return 1
					},
				},
				isWindowsService: true,
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			retCodeCh := make(chan int, 1)
			go func() {
				ep := newEntryPoint(func(ctx context.Context, args []string) int {
					return testCase.runCmdRetCode
				}, testCase.sc)
				retCodeCh <- ep.Main()
			}()

			testCase.sc.initChannels()

			// This is running as a service.
			// Check if we expect a failure running the service.
			if testCase.executeServiceFailure {
				// First status of the service should be Running.
				waitForServiceState(t, testCase.sc.statusCh, svc.Running)

				// Since there was a failure, it should transition to Stopped,
				// first having the StopPending status.
				waitForServiceState(t, testCase.sc.statusCh, svc.StopPending)

				// Final status should be Stopped.
				waitForServiceState(t, testCase.sc.statusCh, svc.Stopped)

				// Assert the return code for Main().
				assertWithTimeout(t, testCase.runCmdRetCode, retCodeCh)

				assert.False(t, testCase.sc.svcSpecificEC)
				assert.Equal(t, uint32(windows.ERROR_FATAL_APP_EXIT), testCase.sc.exitCode)
				return
			}

			status := <-testCase.sc.statusCh
			assert.Equal(t, svc.Running, status.State)

			// Interrogate the service, which should return the current status.
			testCase.sc.changeRequestCh <- svc.ChangeRequest{
				Cmd:           svc.Interrogate,
				CurrentStatus: status,
			}

			waitForServiceState(t, testCase.sc.statusCh, status.State)

			// Stop the service. Status should reflect that's pending to stop.
			testCase.sc.changeRequestCh <- svc.ChangeRequest{Cmd: svc.Stop}
			waitForServiceState(t, testCase.sc.statusCh, svc.StopPending)

			// Next status should be Stopped.
			waitForServiceState(t, testCase.sc.statusCh, svc.Stopped)
		})
	}
}

func TestRunSvcFailure(t *testing.T) {
	tests := []struct {
		name          string
		runCmdRetCode int
		expectRunErr  string
		sc            *fakeSystemCall
	}{
		{
			name:          "svc.Run failure",
			runCmdRetCode: 1,
			sc: &fakeSystemCall{
				args:   runArgs,
				runErr: errors.New("run error"),
				s: service{
					executeServiceFn: func(ctx context.Context, stop context.CancelFunc, args []string) int {
						stop()
						return 0
					},
				},
				isWindowsService: true,
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			retCodeCh := make(chan int, 1)
			go func() {
				ep := newEntryPoint(func(ctx context.Context, args []string) int {
					return testCase.runCmdRetCode
				}, testCase.sc)
				retCodeCh <- ep.Main()
			}()

			testCase.sc.initChannels()

			// First status of the service should be Running.
			waitForServiceState(t, testCase.sc.statusCh, svc.Running)

			// Since there was a failure, it should transition to Stopped,
			// first having the StopPending status.
			waitForServiceState(t, testCase.sc.statusCh, svc.StopPending)

			// Final status should be Stopped.
			waitForServiceState(t, testCase.sc.statusCh, svc.Stopped)

			// Assert the return code for Main().
			assertWithTimeout(t, testCase.runCmdRetCode, retCodeCh)
		})
	}
}

func TestUnsupportedCommand(t *testing.T) {
	tests := []struct {
		name          string
		expectRetCode int
		expectRunErr  string
		sc            *fakeSystemCall
	}{
		{
			name: "service - unsupported command",
			sc: &fakeSystemCall{
				args: []string{"bundle", "show"},
				s: service{
					executeServiceFn: func(ctx context.Context, stop context.CancelFunc, args []string) int {
						return 0
					},
				},
				isWindowsService: true,
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.sc.initChannels()

			ep := newEntryPoint(func(ctx context.Context, args []string) int {
				return 1
			}, testCase.sc)
			assert.Equal(t, 0, ep.Main())
			assert.Equal(t, windows.ERROR_BAD_ARGUMENTS, syscall.Errno(testCase.sc.exitCode))
		})
	}
}

func waitForServiceState(t *testing.T, statusCh chan svc.Status, state svc.State) {
	select {
	case status := <-statusCh:
		assert.Equal(t, state, status.State)
	case <-time.After(time.Second * 5):
		require.FailNow(t, "timed out waiting for service state")
	}
}

func assertWithTimeout(t *testing.T, expectedRetCode int, retCodeCh chan int) {
	select {
	case <-time.After(time.Minute):
		assert.FailNow(t, "timed out waiting for return code")
	case retCode := <-retCodeCh:
		assert.Equal(t, expectedRetCode, retCode)
	}
}
