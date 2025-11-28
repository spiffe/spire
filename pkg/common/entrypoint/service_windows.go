//go:build windows

package entrypoint

import (
	"context"
	"os"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const supportedCommand = "run"

type service struct {
	mtx              sync.RWMutex
	executeServiceFn func(ctx context.Context, stop context.CancelFunc, args []string) int
}

func (s *service) Execute(args []string, changeRequest <-chan svc.ChangeRequest, status chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	// Validate that we are executing the "run" command.
	// First argument (args[0]) is always the process name. Command name is
	// expected in the second argument (args[1]).
	osArgs := os.Args
	if len(osArgs) < 2 || osArgs[1] != supportedCommand {
		if len(args) < 2 || args[1] != supportedCommand {
			return false, uint32(windows.ERROR_BAD_ARGUMENTS)
		}
		osArgs = args
	}

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
		s.mtx.RLock()
		defer s.mtx.RUnlock()
		if retCode = s.executeServiceFn(ctx, stop, osArgs); retCode != 0 {
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
	return false, uint32(retCode) //nolint:gosec // don't care about potential integer conversion overflow
}
