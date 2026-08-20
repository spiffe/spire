package logger

import (
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	apitype "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
)

var APILevel = map[logrus.Level]apitype.LogLevel{
	logrus.PanicLevel: apitype.LogLevel_PANIC,
	logrus.FatalLevel: apitype.LogLevel_FATAL,
	logrus.ErrorLevel: apitype.LogLevel_ERROR,
	logrus.WarnLevel:  apitype.LogLevel_WARN,
	logrus.InfoLevel:  apitype.LogLevel_INFO,
	logrus.DebugLevel: apitype.LogLevel_DEBUG,
	logrus.TraceLevel: apitype.LogLevel_TRACE,
}

var LogrusLevel = map[apitype.LogLevel]logrus.Level{
	apitype.LogLevel_PANIC: logrus.PanicLevel,
	apitype.LogLevel_FATAL: logrus.FatalLevel,
	apitype.LogLevel_ERROR: logrus.ErrorLevel,
	apitype.LogLevel_WARN:  logrus.WarnLevel,
	apitype.LogLevel_INFO:  logrus.InfoLevel,
	apitype.LogLevel_DEBUG: logrus.DebugLevel,
	apitype.LogLevel_TRACE: logrus.TraceLevel,
}

func PrettyPrintLogger(env *commoncli.Env, results ...any) error {
	apiLogger, ok := results[0].(*apitype.Logger)
	if !ok {
		return fmt.Errorf("internal error: unexpected type %T returned; please report this as a bug", results[0])
	}

	logrusCurrent, found := LogrusLevel[apiLogger.CurrentLevel]
	if !found {
		return errors.New("internal error: returned current log level is undefined; please report this as a bug")
	}
	currentText, err := logrusCurrent.MarshalText()
	if err != nil {
		return fmt.Errorf("internal error: logrus log level %d has no name; please report this as a bug", logrusCurrent)
	}

	logrusLaunch, found := LogrusLevel[apiLogger.LaunchLevel]
	if !found {
		return errors.New("internal error: returned launch log level is undefined; please report this as a bug")
	}
	launchText, err := logrusLaunch.MarshalText()
	if err != nil {
		return fmt.Errorf("internal error: logrus log level %d has no name; please report this as a bug", logrusLaunch)
	}

	return env.Printf("Logger Level : %s\nLaunch Level : %s\n\n", currentText, launchText)
}
