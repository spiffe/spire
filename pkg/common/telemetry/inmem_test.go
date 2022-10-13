package telemetry

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMem(t *testing.T) {
	enabled := true
	disabled := false

	for _, tt := range []struct {
		test               string
		inMemConfig        *InMem
		removeLoggerWriter bool
		expectErr          string
		expectEnabled      bool
		expectLogs         []spiretest.LogEntry
	}{
		{
			test:          "disabled when InMem block undeclared",
			inMemConfig:   nil,
			expectEnabled: false,
		},
		{
			test:          "enabled when InMem block declared but deprecated enabled flag unset",
			inMemConfig:   &InMem{},
			expectEnabled: true,
		},
		{
			test:          "enabled when InMem block declared and deprecated enabled flag set to true",
			inMemConfig:   &InMem{DeprecatedEnabled: &enabled},
			expectEnabled: true,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "The enabled flag is deprecated in the InMem configuration and will be removed in a future release; omit the InMem block to disable in-memory telemetry",
				},
			},
		},
		{
			test:          "disabled when InMem block declared and deprecated enabled flag set to false",
			inMemConfig:   &InMem{DeprecatedEnabled: &disabled},
			expectEnabled: false,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "The enabled flag is deprecated in the InMem configuration and will be removed in a future release; omit the InMem block to disable in-memory telemetry",
				},
			},
		},
		{
			test:               "disabled when unexpected logger passed",
			inMemConfig:        &InMem{},
			removeLoggerWriter: true,
			expectEnabled:      false,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Unknown logging subsystem; disabling telemetry signaling",
				},
			},
		},
	} {
		t.Run(tt.test, func(t *testing.T) {
			var logger logrus.FieldLogger
			var hook *test.Hook
			logger, hook = test.NewNullLogger()
			if tt.removeLoggerWriter {
				logger = noWriterLogger(logger)
			}

			runner, err := newInmemRunner(&MetricsConfig{
				Logger:      logger,
				ServiceName: "foo",
				FileConfig:  FileConfig{InMem: tt.inMemConfig},
			})
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				assert.Nil(t, runner)
				return
			}

			require.NoError(t, err)
			if tt.expectEnabled {
				assert.True(t, runner.isConfigured())
				assert.Len(t, runner.sinks(), 1)
			} else {
				assert.False(t, runner.isConfigured())
				assert.Len(t, runner.sinks(), 0)
			}

			spiretest.AssertLogs(t, hook.AllEntries(), tt.expectLogs)
		})
	}
}

func testInmemConfig() *MetricsConfig {
	logger, _ := test.NewNullLogger()
	return &MetricsConfig{
		Logger:      logger,
		ServiceName: "foo",
		FileConfig:  FileConfig{InMem: &InMem{}},
	}
}

func noWriterLogger(logger logrus.FieldLogger) logrus.FieldLogger {
	// Hide the type of the underlying logger to hide the io.Writer
	// implementation
	return struct{ logrus.FieldLogger }{FieldLogger: logger}
}
