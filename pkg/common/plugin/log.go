package plugin

import (
	"io"

	"github.com/sirupsen/logrus"
)

func NullLogger() logrus.FieldLogger {
	logger := logrus.New()
	logger.Out = io.Discard
	return logger
}
