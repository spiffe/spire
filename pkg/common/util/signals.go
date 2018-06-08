package util

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func SignalListener(ctx context.Context, cancel func()) {
	go func() {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

		select {
		case <-ctx.Done():
			return
		case <-signalCh:
			cancel()
		}
	}()
}
