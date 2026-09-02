package log

import (
	"context"
)

// ReopenOnSignal returns a function compatible with RunTasks. Windows has no
// signal to reopen on, so the loop only reports rotation failures that a self
// rotating file could not report itself.
func ReopenOnSignal(logger *Logger, reopener Reopener) func(context.Context) error {
	return func(ctx context.Context) error {
		watchLog(ctx, logger, reopener, nil, rotateErrorInterval)
		return nil
	}
}
