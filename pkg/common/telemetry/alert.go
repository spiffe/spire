package telemetry

import "github.com/sirupsen/logrus"

// AlertFields returns logrus fields that mark a log event as an alert.
func AlertFields(alertType, reason string) logrus.Fields {
	return logrus.Fields{
		Alert:       true,
		AlertType:   alertType,
		AlertReason: reason,
	}
}

// AlertArgs returns hclog key/value pairs that mark a log event as an alert.
func AlertArgs(alertType, reason string) []any {
	return []any{
		Alert, true,
		AlertType, alertType,
		AlertReason, reason,
	}
}
