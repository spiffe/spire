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

func NewLogger(options ...Option) (*Logger, error) {
	logger := &Logger{
		Logger: logrus.New(),
		Closer: nopCloser{},
	}
	logger.SetOutput(os.Stdout)

	for _, option := range options {
		if err := option(logger); err != nil {
			return nil, err
		}
	}

	return logger, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
