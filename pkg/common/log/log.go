package log

import (
	"io"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
)

// Logger is a wrapper struct around logrus.Logger, with a closer
// implementation.
type Logger struct {
	*logrus.Logger
	io.Closer
	useStdout bool
	files     []*os.File
}

// NewLogger creates a logger with the given options.
func NewLogger(options ...Option) (*Logger, error) {
	logger := &Logger{
		Logger: logrus.New(),
	}

	for _, option := range options {
		if err := option(logger); err != nil {
			return nil, err
		}
	}

	// level has now been set, add hooks for the given level
	hookLevels := make([]logrus.Level, 0)
	for _, lvl := range logrus.AllLevels {
		if logger.IsLevelEnabled(lvl) {
			hookLevels = append(hookLevels, lvl)
		}
	}

	for _, file := range logger.files {
		logger.AddHook(&writerHook{
			writer:    file,
			logLevels: hookLevels,
		})
	}

	if logger.useStdout {
		logger.AddHook(&writerHook{
			writer:    os.Stdout,
			logLevels: hookLevels,
		})
	}

	if len(logger.Hooks) == 0 {
		// no hooks (outputs) have been defined, default to standard out
		logger.SetOutput(os.Stdout)
		return logger, nil
	}
	// we have some hooks defined, set regular output to discard,
	// as logging will be handled by the hooks
	logger.SetOutput(ioutil.Discard)
	return logger, nil
}

type writerHook struct {
	writer    io.Writer
	logLevels []logrus.Level
}

func (hook *writerHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	_, err = hook.writer.Write([]byte(line))
	return err
}

func (hook *writerHook) Levels() []logrus.Level {
	return hook.logLevels
}

func (l Logger) Close() error {
	for _, c := range l.files {
		if err := c.Close(); err != nil {
			return err
		}
	}
	return nil
}
