//go:build !windows

package log

import (
	"context"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

const reopenSignal = unix.SIGUSR2

// ReopenOnSignal returns a function compatible with RunTasks.
func ReopenOnSignal(logger *Logger, reopener Reopener) func(context.Context) error {
	return func(ctx context.Context) error {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, reopenSignal)
		defer signal.Stop(signalCh)

		watchLog(ctx, logger, reopener, signalCh, rotateErrorInterval)
		return nil
	}
}
