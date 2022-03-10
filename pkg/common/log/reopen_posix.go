//go:build !windows

package log

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

const (
	reopenSignal = syscall.SIGUSR2
)

// ReopenOnSignal returns a function compatible with RunTasks.
func ReopenOnSignal(logger *Logger, reopener Reopener) func(context.Context) error {
	return func(ctx context.Context) error {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, reopenSignal)
		return reopenOnSignal(ctx, logger, reopener, signalCh)
	}
}

func reopenOnSignal(
	ctx context.Context,
	logger *Logger,
	reopener Reopener,
	signalCh chan os.Signal,
) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-signalCh:
			if err := reopener.Reopen(logger); err != nil {
				return err
			}
		}
	}
}
