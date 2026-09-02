package log

import (
	"context"
	"time"
)

// rotateErrorInterval is how often a self rotating file is asked whether a
// rotation failed. Rotation is driven by writes, so there is nothing to react
// to and polling is enough.
const rotateErrorInterval = time.Minute

const failedToRotateMsg = "failed to rotate log"

// rotateErrorSource is implemented by writers that rotate themselves and cannot
// report a failure from inside Write.
type rotateErrorSource interface {
	TakeRotateError() error
}

// reportRotateErrors logs rotation failures until ctx is done. Without it a
// self rotating file that keeps failing would grow silently, since Reopen is
// the only other path that surfaces the error and nothing triggers it on
// Windows.
func reportRotateErrors(ctx context.Context, logger *Logger, reopener Reopener, interval time.Duration) {
	source, ok := reopener.(rotateErrorSource)
	if !ok {
		<-ctx.Done()
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := source.TakeRotateError(); err != nil {
				logger.WithError(err).Error(failedToRotateMsg)
			}
		}
	}
}
