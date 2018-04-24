package grpcutil

import (
	"log"

	"github.com/sirupsen/logrus"
)

func LoggerFromFieldLogger(fl logrus.FieldLogger) logrus.StdLogger {
	errWriter := fl.WithFields(logrus.Fields{}).WriterLevel(logrus.ErrorLevel)
	return log.New(errWriter, "", 0)
}
