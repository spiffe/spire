package plugin

import "github.com/sirupsen/logrus"

// Log provides a plugin logger to version shim implementations.
type Log struct {
	logrus.FieldLogger
}
