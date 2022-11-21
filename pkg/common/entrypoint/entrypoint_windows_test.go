//go:build windows
// +build windows

package entrypoint

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

type fakeSystemCall struct {
	s               service
	args            []string
	changeRequestCh chan svc.ChangeRequest
	statusCh        chan svc.Status

	svcSpecificEC bool
	exitCode      uint32

	isWindowsService    bool
	isWindowsServiceErr error
	runErr              error
}

func (s *fakeSystemCall) IsWindowsService() (bool, error) {
	return s.isWindowsService, s.isWindowsServiceErr
}

func (s *fakeSystemCall) Run(name string, handler svc.Handler) error {
	var (
		wg            sync.WaitGroup
		svcSpecificEC bool
		exitCode      uint32
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		svcSpecificEC, exitCode = s.s.Execute(s.args, s.changeRequestCh, s.statusCh)
	}()

	wg.Wait()
	s.statusCh <- svc.Status{State: svc.Stopped}
	s.svcSpecificEC = svcSpecificEC
	s.exitCode = exitCode
	return s.runErr
}

func newEntryPoint(runCmdFn func(ctx context.Context, args []string) int, sc systemCaller) *EntryPoint {
	return &EntryPoint{
		handler: &service{
			RunFn: func(ctx context.Context, stop context.CancelFunc, args []string) int {
				retCode := runCmdFn(ctx, args[1:])
				stop()
				return retCode
			},
		},
		runCmdFn: runCmdFn,
		sc:       sc,
	}
}

func TestEntryPoint(t *testing.T) {
	tests := []struct {
		name         string
		retCode      int
		expectRunErr string
		sc           *fakeSystemCall
	}{
		{
			name: "not a service - success",
			sc:   &fakeSystemCall{},
		},
		{
			name:    "not a service - failure",
			retCode: 1,
			sc:      &fakeSystemCall{},
		},
		{
			name: "service - success",
			sc: &fakeSystemCall{
				s: service{
					RunFn: func(ctx context.Context, stop context.CancelFunc, args []string) int {
						return 0
					},
				},
				isWindowsService: true,
				changeRequestCh:  make(chan svc.ChangeRequest, 1),
				statusCh:         make(chan svc.Status, 1),
			},
		},
		{
			name: "service - fatal app exit",
			sc: &fakeSystemCall{
				s: service{
					RunFn: func(ctx context.Context, stop context.CancelFunc, args []string) int {
						stop()
						return 1
					},
				},
				isWindowsService: true,
				changeRequestCh:  make(chan svc.ChangeRequest, 1),
				statusCh:         make(chan svc.Status, 1),
			},
		},
		{
			name: "service - run failure",
			sc: &fakeSystemCall{
				runErr: errors.New("run failure"),
				s: service{
					RunFn: func(ctx context.Context, stop context.CancelFunc, args []string) int {
						stop()
						return 1
					},
				},
				isWindowsService: true,
				changeRequestCh:  make(chan svc.ChangeRequest, 1),
				statusCh:         make(chan svc.Status, 1),
			},
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

			if !testCase.sc.isWindowsService {
				// Not a service, just check for the return code
				assert.Equal(t, testCase.retCode, <-retCodeCh)
				return
			}

			// This is running as a service.
			// Check if we expect a failure running the service.
			if testCase.retCode != 0 {
				assert.Equal(t, testCase.retCode, <-retCodeCh)

				// First status of the service should be Running.
				assert.Equal(t, svc.Running, (<-testCase.sc.statusCh).State)

				// Since there was a failure, it should transition to Stopped,
				// first having the StopPending status.
				assert.Equal(t, svc.StopPending, (<-testCase.sc.statusCh).State)

				// Final status should be Stopped.
				assert.Equal(t, svc.Stopped, (<-testCase.sc.statusCh).State)

				assert.Equal(t, false, testCase.sc.svcSpecificEC)
				assert.Equal(t, windows.ERROR_FATAL_APP_EXIT, testCase.sc.exitCode)
				return
			}

			status := <-testCase.sc.statusCh
			assert.Equal(t, svc.Running, status.State)

			// Stop the service. Status should reflect that's pending to stop.
			testCase.sc.changeRequestCh <- svc.ChangeRequest{Cmd: svc.Stop}
			waitForServiceState(t, testCase.sc.statusCh, svc.StopPending)

			// Next status should be Stopped.
			waitForServiceState(t, testCase.sc.statusCh, svc.Stopped)
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
