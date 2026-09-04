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
	failedToReopenMsg = "failed to reopen log file"
	failedToRotateMsg = "failed to rotate log"
)

// rotateErrorSource is implemented by writers that rotate themselves and cannot
// report a failure from inside Write.
type rotateErrorSource interface {
	TakeRotateError() error
}

// rotateErrorTicker returns the channel that paces draining of rotation
// failures, or nil when the writer has none to report. A receive on a nil
// channel blocks forever, so the caller needs no special case.
func rotateErrorTicker(reopener Reopener) (<-chan time.Time, func()) {
	if _, ok := reopener.(rotateErrorSource); !ok {
		return nil, func() {}
	}
	ticker := time.NewTicker(rotateErrorInterval)
	return ticker.C, ticker.Stop
}

// watchLog reopens the log on every value from signalCh or requestCh, and
// drains rotation failures on every value from tickCh. A channel is nil where
// that source does not apply, signalCh on Windows, requestCh on POSIX, and
// tickCh for a writer that does not rotate itself, so both platforms run the
// same loop.
func watchLog(ctx context.Context, logger *Logger, reopener Reopener, signalCh <-chan os.Signal, requestCh <-chan struct{}, tickCh <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-signalCh:
			reopenLog(logger, reopener)
		case <-requestCh:
			reopenLog(logger, reopener)
		case <-tickCh:
			source, ok := reopener.(rotateErrorSource)
			if !ok {
				continue
			}
			if err := source.TakeRotateError(); err != nil {
				logger.WithError(err).Error(failedToRotateMsg)
			}
		}
	}
}

// reopenLog is shared by the two triggers, a signal on POSIX and a service
// control request on Windows.
func reopenLog(logger *Logger, reopener Reopener) {
	if err := reopener.Reopen(); err != nil {
		// never fail; best effort to log to old file descriptor
		logger.WithError(err).Error(failedToReopenMsg)
	}
}
