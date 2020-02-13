package log

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultFormat signifies the default logrus format
	DefaultFormat = ""
	// JSONFormat signifies JSON logging format
	JSONFormat = "JSON"
	// TextFormat signifies Text logging format
	TextFormat = "TEXT"
)

// An Option can change the Logger to apply desired configuration in NewLogger
type Option func(*Logger) error

// WithStdOut configures logger to log with a `stdout` hook
func WithStdOut() Option {
	return func(logger *Logger) error {
		logger.useStdout = true
		return nil
	}
}

// WithOutputFile configures logger to log with a hook to the given file
func WithOutputFile(file string) Option {
	return func(logger *Logger) error {
		if file == "" {
			return nil
		}

		fd, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return err
		}

		// setting writing for the file is saved for Logger construction, after the
		// logging Level is known

		logger.files = append(logger.files, fd)
		return nil
	}
}

// WithFormat configures logger to log in the given format
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

// WithLevel configures logger to log at the given level
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
