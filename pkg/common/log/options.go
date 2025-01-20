package log

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	DefaultFormat = ""
	JSONFormat    = "JSON"
	TextFormat    = "TEXT"
)

// An Option can change the Logger to apply desired configuration in NewLogger
type Option func(*Logger) error

// WithOutputFile requires lossy copytruncate directive in logrotate.
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

// WithReopenableOutputFile uses ReopenableFile to support handling a signal
// to rotate log files (e.g. from a logrotate postrotate script).
func WithReopenableOutputFile(reopenableFile *ReopenableFile) Option {
	return func(logger *Logger) error {
		logger.SetOutput(reopenableFile)

		// If, for some reason, there's another closer set, close it first.
		if logger.Closer != nil {
			if err := logger.Closer.Close(); err != nil {
				return err
			}
		}

		logger.Closer = reopenableFile
		return nil
	}
}

func WithFormat(format string) Option {
	return func(logger *Logger) error {
		switch strings.ToUpper(format) {
		case DefaultFormat:
			// Logrus has a default formatter set up in logrus.New(), so we don't change it
		case JSONFormat:
			logger.Formatter = &logrus.JSONFormatter{
				TimestampFormat: time.RFC3339Nano,
			}
		case TextFormat:
			logger.Formatter = &logrus.TextFormatter{
				TimestampFormat: time.RFC3339Nano,
			}
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

func WithSourceLocation() Option {
	return func(logger *Logger) error {
		// logrus provides a built-in feature that is very close to what we
		// want (logger.SetReportCaller). Unfortunately, it always reports the
		// immediate caller; but in certain cases, we want to skip over some
		// more frames; in particular, this applies to the HCLogAdapter.
		logger.AddHook(sourceLocHook{})
		return nil
	}
}

type sourceLocHook struct{}

func (sourceLocHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (sourceLocHook) Fire(e *logrus.Entry) error {
	frame := getCaller()
	if frame != nil {
		e.Data[logrus.FieldKeyFile] = fmt.Sprintf("%s:%d", filepath.Base(frame.File), frame.Line)
		e.Data[logrus.FieldKeyFunc] = frame.Function
	}
	return nil
}

func getCaller() *runtime.Frame {
	pcs := make([]uintptr, 10)
	skip := 3 // skip 'runtime.Callers', this function, and its caller
	numPcs := runtime.Callers(skip, pcs)
	if numPcs == 0 {
		return nil
	}
	frames := runtime.CallersFrames(pcs[:numPcs])

	for {
		f, more := frames.Next()

		// skip over frames within the logging infrastructure
		if !isLoggingFunc(f.Function) {
			return &f
		}

		if !more {
			break
		}
	}

	return nil
}

var loggingFuncRegexp = regexp.MustCompile(
	`^github\.com/(?:sirupsen/logrus|spiffe/spire/pkg/common/log)[./]`)

func isLoggingFunc(funcName string) bool {
	return loggingFuncRegexp.MatchString(funcName) &&
		!strings.HasPrefix(funcName, "github.com/spiffe/spire/pkg/common/log.Test")
}
