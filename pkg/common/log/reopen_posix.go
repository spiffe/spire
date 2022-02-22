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
func ReopenOnSignal(reopener Reopener) func(context.Context) error {
	return func(ctx context.Context) error {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, reopenSignal)
		return reopenOnSignal(ctx, reopener, signalCh)
	}
}

func reopenOnSignal(
	ctx context.Context,
	reopener Reopener,
	signalCh chan os.Signal,
) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-signalCh:
			if err := reopener.Reopen(); err != nil {
				return err
			}
		}
	}
}
