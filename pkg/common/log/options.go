package log

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	DefaultFormat = ""
	JSONFormat    = "JSON"
	TextFormat    = "TEXT"
)

// An Option can change the Logger to apply desired configuration in NewLogger
type Option func(*Logger) error

func WithOutputFile(file string) Option {
	return func(logger *Logger) error {
		if file == "" {
			return nil
		}
		fd, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return err
		}

		logger.SetOutput(fd)

		// If, for some reason, there's another closer set, close it first.
		if logger.Closer != nil {
			if err := logger.Closer.Close(); err != nil {
				return err
			}
		}

		logger.Closer = fd
		return nil
	}
}

func WithFormat(format string) Option {
	return func(logger *Logger) error {
		switch strings.ToUpper(format) {
		case DefaultFormat:
			// Logrus has a default formatter set up in logrus.New(), so we don't change it
		case JSONFormat:
			logger.Formatter = &logrus.JSONFormatter{}
		case TextFormat:
			logger.Formatter = &logrus.TextFormatter{}
		default:
			return fmt.Errorf("unknown logger format: %q", format)
		}
		return nil
	}
}

func WithLevel(logLevel string) Option {
	return func(logger *Logger) error {
		level, err := logrus.ParseLevel(logLevel)
		if err != nil {
			return err
		}
		logger.SetLevel(level)
		return nil
	}
}
