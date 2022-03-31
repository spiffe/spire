package util

import (
	"context"
	"os/signal"
	"syscall"
)

func SignalListener(parent context.Context, cancel func()) {
	go func() {
		ctx, cancel := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)

		select {
		case <-parent.Done():
		case <-ctx.Done():
			cancel()
		}
	}()
}
