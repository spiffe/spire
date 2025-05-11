package logger

import (
	"github.com/sirupsen/logrus"
	apitype "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
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
