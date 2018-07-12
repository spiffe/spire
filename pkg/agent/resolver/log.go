package resolver

import (
	"log"

	"github.com/sirupsen/logrus"
)

func LoggerFromFieldLogger(fl logrus.FieldLogger) logrus.StdLogger {
	if fl != nil {
		errWriter := fl.WithFields(logrus.Fields{}).WriterLevel(logrus.WarnLevel)
		return log.New(errWriter, "", 0)
	} else {
		return logrus.New()
	}
}
