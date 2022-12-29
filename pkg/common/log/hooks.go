package log

import (
	"time"

	"github.com/sirupsen/logrus"
)

// LocalTimeHook is a logrus hook that converts all log fields with type time.Time to local time.
type LocalTimeHook struct{}

// Levels defines on which log levels this hook would trigger.
func (l LocalTimeHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire is called when one of the log levels defined in Levels() is triggered.
func (l LocalTimeHook) Fire(entry *logrus.Entry) error {
	// Convert all log fields with type time.Time to local time.
	for k, v := range entry.Data {
		if t, ok := v.(time.Time); ok {
			entry.Data[k] = t.Local()
		}
	}
	return nil
}
