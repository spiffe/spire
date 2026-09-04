//go:build windows

package log

import (
	"context"
)

// ReopenOnSignal returns a function compatible with RunTasks. Windows has no
// signal to reopen on, so the request arrives from the service control handler
// by way of RequestReopen.
func ReopenOnSignal(logger *Logger, reopener Reopener) func(context.Context) error {
	return func(ctx context.Context) error {
		tickCh, stopTicker := rotateErrorTicker(reopener)
		defer stopTicker()

		watchLog(ctx, logger, reopener, nil, reopenRequests, tickCh)
		return nil
	}
}
