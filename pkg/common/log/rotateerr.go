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

// rotateErrorDrain reports the rotation failures a self rotating writer could
// not report itself, paced by tickCh. The zero value is what a writer with
// nothing to drain gets, and its nil tickCh never fires, so report is only ever
// reached when there is a source behind it.
type rotateErrorDrain struct {
	source rotateErrorSource
	tickCh <-chan time.Time
}

// newRotateErrorDrain returns the drain for reopener along with a stop for the
// ticker behind it.
func newRotateErrorDrain(reopener Reopener) (rotateErrorDrain, func()) {
	source, ok := reopener.(rotateErrorSource)
	if !ok {
		return rotateErrorDrain{}, func() {}
	}
	ticker := time.NewTicker(rotateErrorInterval)
	return rotateErrorDrain{source: source, tickCh: ticker.C}, ticker.Stop
}

func (d rotateErrorDrain) report(logger *Logger) {
	if err := d.source.TakeRotateError(); err != nil {
		logger.WithError(err).Error(failedToRotateMsg)
	}
}

// watchLog reopens the log on every value from signalCh or requestCh, and
// drains rotation failures as the drain paces them. A trigger channel is nil on
// the platform that lacks it, signalCh on Windows and requestCh on POSIX, so
// both platforms run the same loop.
//
//nolint:unparam // the caller passing the other trigger is behind the opposite build tag
func watchLog(ctx context.Context, logger *Logger, reopener Reopener, signalCh <-chan os.Signal, requestCh <-chan struct{}, drain rotateErrorDrain) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-signalCh:
			reopenLog(logger, reopener)
		case <-requestCh:
			reopenLog(logger, reopener)
		case <-drain.tickCh:
			drain.report(logger)
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
