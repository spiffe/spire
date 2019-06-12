package log

import (
	"fmt"
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

const (
	DefaultFormat = ""
	JSONFormat    = "JSON"
	TextFormat    = "TEXT"
)

func NewLogger(logLevel, format, fileName string) (logrus.FieldLogger, error) {
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

	switch format {
	case DefaultFormat:
		// Logrus has a default formatter set up in logrus.New(), so we don't change it
	case JSONFormat:
		logger.Formatter = &logrus.JSONFormatter{}
	case TextFormat:
		logger.Formatter = &logrus.TextFormatter{}
	default:
		return nil, fmt.Errorf("unknown logger format: '%s'", format)
	}

	return logger, nil
}
