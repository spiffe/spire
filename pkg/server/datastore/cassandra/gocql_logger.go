package cassandra

import (
	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/sirupsen/logrus"
)

type driverLogLevel string

const (
	DriverLogLevelDebug driverLogLevel = "DEBUG"
	DriverLogLevelInfo  driverLogLevel = "INFO"
	DriverLogLevelWarn  driverLogLevel = "WARN"
	DriverLogLevelError driverLogLevel = "ERROR"
	DriverLogLevelOff   driverLogLevel = "OFF"
)

var driverLogLevelMap = map[driverLogLevel]int{
	DriverLogLevelDebug: 1,
	DriverLogLevelInfo:  2,
	DriverLogLevelWarn:  3,
	DriverLogLevelError: 4,
	DriverLogLevelOff:   5,
}

// wrappedLogger is a wrapper around the logrus logger provided to the plugin
// to satisfy the gocql.Logger interface. It simply forwards log messages from the
// gocql driver to the provided logrus logger.
//
// This logger can be used to capture and redirect logs from the gocql driver
// to the application's logging system, allowing for consistent log formatting
// and handling across the application.
type wrappedLogger struct {
	logger logrus.FieldLogger
	level  driverLogLevel
}

// Error logs an error message with the provided fields.
func (w *wrappedLogger) Error(msg string, fields ...gocql.LogField) {
	if driverLogLevelMap[w.level] > driverLogLevelMap[DriverLogLevelError] {
		return
	}

	l := w.logger.WithFields(logrus.Fields{})

	for _, field := range fields {
		l = l.WithField(field.Name, field.Value)
	}
	l.Errorf("gocql-driver: %s", msg)
}

// Warning logs a warning message with the provided fields.
func (w *wrappedLogger) Warning(msg string, fields ...gocql.LogField) {
	if driverLogLevelMap[w.level] > driverLogLevelMap[DriverLogLevelWarn] {
		return
	}

	l := w.logger.WithFields(logrus.Fields{})

	for _, field := range fields {
		l = l.WithField(field.Name, field.Value)
	}
	l.Warnf("gocql-driver: %s", msg)
}

// Info logs an informational message with the provided fields.
func (w *wrappedLogger) Info(msg string, fields ...gocql.LogField) {
	if driverLogLevelMap[w.level] > driverLogLevelMap[DriverLogLevelInfo] {
		return
	}

	l := w.logger.WithFields(logrus.Fields{})

	for _, field := range fields {
		l = l.WithField(field.Name, field.Value)
	}
	l.Infof("gocql-driver: %s", msg)
}

// Debug logs a debug message with the provided fields.
func (w *wrappedLogger) Debug(msg string, fields ...gocql.LogField) {
	if driverLogLevelMap[w.level] > driverLogLevelMap[DriverLogLevelDebug] {
		return
	}

	l := w.logger.WithFields(logrus.Fields{})

	for _, field := range fields {
		l = l.WithField(field.Name, field.Value)
	}
	l.Debugf("gocql-driver: %s", msg)
}
