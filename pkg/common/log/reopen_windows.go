//go:build windows

package log

import (
	"context"
)

// ReopenOnSignal returns a noop function compatible with RunTasks since
// windows does not have signals as on *nix.
func ReopenOnSignal(*Logger, Reopener) func(context.Context) error {
	return func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}
}
