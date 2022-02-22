//go:build windows

package log

import (
	"context"
)

// ReopenOnSignal returns a function compatible with RunTasks.
func ReopenOnSignal(reopener Reopener) func(context.Context) error {
	return func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}
}
