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

type Logger struct {
	*logrus.Logger
	io.Closer
}

func NewLogger(logLevel, format, fileName string) (*Logger, error) {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return nil, err
	}

	var out io.Writer = os.Stdout
	var closer io.Closer = nopCloser{}
	if fileName != "" {
		fd, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return nil, err
		}
		out = fd
		closer = fd
	}

	logger := logrus.New()
	logger.SetOutput(out)
	logger.SetLevel(level)

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

	return &Logger{
		Logger: logger,
		Closer: closer,
	}, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
