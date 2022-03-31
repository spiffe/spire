//go:build !windows

package log

import (
	"context"
	"os/signal"
	"syscall"
)

const (
	reopenSignal      = syscall.SIGUSR2
	failedToReopenMsg = "failed to rotate log after signal"
)

// ReopenOnSignal returns a function compatible with RunTasks.
func ReopenOnSignal(logger *Logger, reopener Reopener) func(context.Context) error {
	return func(parent context.Context) error {
		ctx, cancel := signal.NotifyContext(parent, reopenSignal)
		return reopenOnSignal(parent, ctx, cancel, logger, reopener)
	}
}

func reopenOnSignal(
	parent context.Context,
	ctx context.Context,
	cancel context.CancelFunc,
	logger *Logger,
	reopener Reopener,
) error {
	for {
		select {
		case <-parent.Done():
			cancel()
			return nil
		case <-ctx.Done():
			if err := reopener.Reopen(); err != nil {
				// never fail; best effort to log to old file descriptor
				logger.WithError(err).Error(failedToReopenMsg)
			}
		}
	}
}
