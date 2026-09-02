//go:build !windows

package log

import (
	"context"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

const (
	reopenSignal      = unix.SIGUSR2
	failedToReopenMsg = "failed to rotate log after signal"
)

// ReopenOnSignal returns a function compatible with RunTasks.
func ReopenOnSignal(logger *Logger, reopener Reopener) func(context.Context) error {
	return func(ctx context.Context) error {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, reopenSignal)
		defer signal.Stop(signalCh)

		// Rotation failures are reported alongside the signal handling, since a
		// size triggered rotation can fail without anyone sending a signal.
		go reportRotateErrors(ctx, logger, reopener, rotateErrorInterval)

		reopenOnSignal(ctx, logger, reopener, signalCh)
		return nil
	}
}

func reopenOnSignal(
	ctx context.Context,
	logger *Logger,
	reopener Reopener,
	signalCh chan os.Signal,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-signalCh:
			if err := reopener.Reopen(); err != nil {
				// never fail; best effort to log to old file descriptor
				logger.WithError(err).Error(failedToReopenMsg)
			}
		}
	}
}
