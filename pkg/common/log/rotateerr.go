package log

import (
	"context"
	"os"
	"time"
)

// rotateErrorInterval is how often a self rotating file is asked whether a
// rotation failed. Rotation is driven by writes, so there is nothing to react
// to and polling is enough.
const rotateErrorInterval = time.Minute

const (
	failedToReopenMsg = "failed to rotate log after signal"
	failedToRotateMsg = "failed to rotate log"
)

// rotateErrorSource is implemented by writers that rotate themselves and cannot
// report a failure from inside Write.
type rotateErrorSource interface {
	TakeRotateError() error
}

// watchLog reopens the log on every value from signalCh and reports rotation
// failures that the writer could not report itself. signalCh is nil on
// platforms without a reopen signal, and a receive on a nil channel blocks
// forever, so both platforms run the same loop.
func watchLog(ctx context.Context, logger *Logger, reopener Reopener, signalCh <-chan os.Signal, interval time.Duration) {
	// Only a self rotating file has failures to drain.
	source, _ := reopener.(rotateErrorSource)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-signalCh:
			if err := reopener.Reopen(); err != nil {
				// never fail; best effort to log to old file descriptor
				logger.WithError(err).Error(failedToReopenMsg)
			}
		case <-ticker.C:
			if source == nil {
				continue
			}
			if err := source.TakeRotateError(); err != nil {
				logger.WithError(err).Error(failedToRotateMsg)
			}
		}
	}
}
