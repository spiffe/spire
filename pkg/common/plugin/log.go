package plugin

import (
	"io/ioutil"

	"github.com/sirupsen/logrus"
)

func NullLogger() logrus.FieldLogger {
	logger := logrus.New()
	logger.Out = ioutil.Discard
	return logger
}
