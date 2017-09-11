package helpers

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

func NewLogger(logLevel string, fileName string) (logrus.FieldLogger, error) {
	var fd io.Writer
	var err error

	if fileName != "" {
		fd, err = os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return nil, err
		}
	} else {
		fd = os.Stdout
	}

	logrusLevel, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return nil, err
	}

	logger := logrus.New()
	logger.Out = fd
	logger.Level = logrusLevel

	return logger, nil
}
