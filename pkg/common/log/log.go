package log

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
	io.Closer
}

func NewLogger(logLevel string, fileName string) (*Logger, error) {
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

	return &Logger{
		Logger: logger,
		Closer: closer,
	}, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
