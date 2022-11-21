//go:build windows
// +build windows

package entrypoint

import (
	"context"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

type service struct {
	RunFn func(ctx context.Context, stop context.CancelFunc, args []string) int
}

func (s *service) Execute(args []string, changeRequest <-chan svc.ChangeRequest, status chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	// Update the status to indicate that SPIRE is running.
	// Only Stop and Shutdown commands are accepted (Interrogate is always accepted).
	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	var (
		wg      sync.WaitGroup
		retCode int
	)
	ctx, stop := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		if retCode = s.RunFn(ctx, stop, args); retCode != 0 {
			retCode = int(windows.ERROR_FATAL_APP_EXIT)
		}
	}()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case c := <-changeRequest:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			}
		}
	}

	status <- svc.Status{State: svc.StopPending}
	stop()
	wg.Wait()
	return false, uint32(retCode)
}
