package logger_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api/logger/v1"
)

func TestAPILevelValues(t *testing.T) {
	for _, tt := range []struct {
		name          string
		logrusLevel   logrus.Level
		expectedLevel types.LogLevel
	}{
		{
			name:          "test logrus.PanicLevel fetches types.LogLevel_PANIC",
			logrusLevel:   logrus.PanicLevel,
			expectedLevel: types.LogLevel_PANIC,
		},
		{
			name:          "test logrus.FatalLevel fetches types.LogLevel_FATAL",
			logrusLevel:   logrus.FatalLevel,
			expectedLevel: types.LogLevel_FATAL,
		},
		{
			name:          "test logrus.ErrorLevel fetches types.LogLevel_ERROR",
			logrusLevel:   logrus.ErrorLevel,
			expectedLevel: types.LogLevel_ERROR,
		},
		{
			name:          "test logrus.WarnLevel fetches types.LogLevel_WARN",
			logrusLevel:   logrus.WarnLevel,
			expectedLevel: types.LogLevel_WARN,
		},
		{
			name:          "test logrus.InfoLevel fetches types.LogLevel_INFO",
			logrusLevel:   logrus.InfoLevel,
			expectedLevel: types.LogLevel_INFO,
		},
		{
			name:          "test logrus.DebugLevel fetches types.LogLevel_DEBUG",
			logrusLevel:   logrus.DebugLevel,
			expectedLevel: types.LogLevel_DEBUG,
		},
		{
			name:          "test logrus.TraceLevel fetches types.LogLevel_TRACE",
			logrusLevel:   logrus.TraceLevel,
			expectedLevel: types.LogLevel_TRACE,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, logger.APILevel[tt.logrusLevel], tt.expectedLevel)
		})
	}
}

func TestLogrusLevelValues(t *testing.T) {
	for _, tt := range []struct {
		name          string
		apiLevel      types.LogLevel
		expectedLevel logrus.Level
	}{
		{
			name:          "test types.LogLevel_PANIC fetches logrus.PanicLevel",
			apiLevel:      types.LogLevel_PANIC,
			expectedLevel: logrus.PanicLevel,
		},
		{
			name:          "test types.LogLevel_FATAL fetches logrus.FatalLevel",
			apiLevel:      types.LogLevel_FATAL,
			expectedLevel: logrus.FatalLevel,
		},
		{
			name:          "test types.LogLevel_ERROR fetches logrus.ErrorLevel",
			apiLevel:      types.LogLevel_ERROR,
			expectedLevel: logrus.ErrorLevel,
		},
		{
			name:          "test types.LogLevel_WARN fetches logrus.WarnLevel",
			apiLevel:      types.LogLevel_WARN,
			expectedLevel: logrus.WarnLevel,
		},
		{
			name:          "test types.LogLevel_INFO fetches logrus.InfoLevel",
			apiLevel:      types.LogLevel_INFO,
			expectedLevel: logrus.InfoLevel,
		},
		{
			name:          "test types.LogLevel_DEBUG fetches logrus.DebugLevel",
			apiLevel:      types.LogLevel_DEBUG,
			expectedLevel: logrus.DebugLevel,
		},
		{
			name:          "test types.LogLevel_TRACE fetches logrus.TraceLevel",
			apiLevel:      types.LogLevel_TRACE,
			expectedLevel: logrus.TraceLevel,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, logger.LogrusLevel[tt.apiLevel], tt.expectedLevel)
		})
	}
}
