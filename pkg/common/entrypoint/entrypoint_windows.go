//go:build windows
// +build windows

package entrypoint

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
)

type systemCaller interface {
	IsWindowsService() (bool, error)
	Run(name string, handler svc.Handler) error
}

type systemCall struct {
}

func (s *systemCall) IsWindowsService() (bool, error) {
	return svc.IsWindowsService()
}

func (s *systemCall) Run(name string, handler svc.Handler) error {
	return svc.Run(name, handler)
}

type EntryPoint struct {
	handler  svc.Handler
	runCmdFn func(ctx context.Context, args []string) int
	sc       systemCaller
}

func NewEntryPoint(runCmdFn func(ctx context.Context, args []string) int) *EntryPoint {
	return &EntryPoint{
		runCmdFn: runCmdFn,
		handler: &service{
			RunFn: func(ctx context.Context, stop context.CancelFunc, args []string) int {
				retCode := runCmdFn(ctx, args[1:])
				stop()
				return retCode
			},
		},
		sc: &systemCall{},
	}
}

func (e *EntryPoint) Main() int {
	isWindowsService, err := e.sc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not determine if running as a Windows service: %v", err)
		return 1
	}
	if isWindowsService {
		errChan := make(chan error)
		go func() {
			// Since the service runs in its own process, the service name is ignored.
			// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw
			errChan <- e.sc.Run("", e.handler)
		}()
		err = <-errChan
		if err != nil {
			return 1
		}
		return 0
	}

	return e.runCmdFn(context.Background(), os.Args[1:])
}
