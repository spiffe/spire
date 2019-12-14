package health

import (
	"github.com/InVisionApp/go-health"
	"github.com/InVisionApp/go-logger"
	"github.com/sirupsen/logrus"
)

// statusListener logs
type statusListener struct {
	log logrus.FieldLogger
}

// Assert statusListener implements IStatusListener
var _ health.IStatusListener = &statusListener{}

// HealthCheckFailed is triggered when a health check fails the first time
func (sl *statusListener) HealthCheckFailed(entry *health.State) {
	sl.log.WithField("check", entry.Name).
		WithField("details", entry.Details).
		WithField("error", entry.Err).
		Warn("Health check failed")
}

// HealthCheckRecovered is triggered when a health check recovers
func (sl *statusListener) HealthCheckRecovered(entry *health.State, recordedFailures int64, failureDurationSeconds float64) {
	sl.log.WithField("check", entry.Name).
		WithField("details", entry.Details).
		WithField("error", entry.Err).
		WithField("failures", recordedFailures).
		WithField("duration", failureDurationSeconds).
		Info("Health check recovered")
}

// logadapter adapts types between InVisionApp/go-logger and logrus
type logadapter struct {
	logrus.FieldLogger
}

// WithFields wraps logrus.Fieldlogger to implement the Logger interface in InVisionApp/go-logger
func (l *logadapter) WithFields(fields log.Fields) log.Logger {
	return &logadapter{
		FieldLogger: l.FieldLogger.WithFields(logrus.Fields(fields)),
	}
}
