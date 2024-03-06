package logger_test

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/test/grpctest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"

	"github.com/sirupsen/logrus"
	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	apitype "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api/logger/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func TestGetLogger(t *testing.T) {
	for _, tt := range []struct {
		name        string
		launchLevel logrus.Level

		expectedErr      error
		expectedResponse *apitype.Logger
		expectedLogs     []spiretest.LogEntry
	}{
		{
			name:        "test GetLogger on initialized to PANIC",
			launchLevel: logrus.PanicLevel,

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_PANIC,
				LaunchLevel:  apitype.LogLevel_PANIC,
			},
			// no outputted log messages, as the are at INFO level
			expectedLogs: nil,
		},
		{
			name:        "test GetLogger on initialized to FATAL",
			launchLevel: logrus.FatalLevel,

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_FATAL,
				LaunchLevel:  apitype.LogLevel_FATAL,
			},
			// no outputted log messages, as the are at INFO level
			expectedLogs: nil,
		},
		{
			name:        "test GetLogger on initialized to ERROR",
			launchLevel: logrus.ErrorLevel,

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_ERROR,
				LaunchLevel:  apitype.LogLevel_ERROR,
			},
			// no outputted log messages, as the are at INFO level
			expectedLogs: nil,
		},
		{
			name:        "test GetLogger on initialized to WARN",
			launchLevel: logrus.WarnLevel,

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_WARN,
				LaunchLevel:  apitype.LogLevel_WARN,
			},
			// no outputted log messages, as the are at INFO level
			expectedLogs: nil,
		},
		{
			name:        "test GetLogger on initialized to INFO",
			launchLevel: logrus.InfoLevel,

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_INFO,
				LaunchLevel:  apitype.LogLevel_INFO,
			},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test GetLogger on initialized to DEBUG",
			launchLevel: logrus.DebugLevel,

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_DEBUG,
				LaunchLevel:  apitype.LogLevel_DEBUG,
			},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "debug",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test GetLogger on initialized to TRACE",
			launchLevel: logrus.TraceLevel,

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_TRACE,
				LaunchLevel:  apitype.LogLevel_TRACE,
			},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "trace",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, tt.launchLevel)
			defer test.Cleanup()

			resp, err := test.client.GetLogger(context.Background(), &loggerv1.GetLoggerRequest{})
			require.Equal(t, err, tt.expectedErr)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectedLogs)
			spiretest.RequireProtoEqual(t, resp, tt.expectedResponse)
		})
	}
}

// After changing the log level, gets the logger to check the log impact
func TestSetLoggerThenGetLogger(t *testing.T) {
	for _, tt := range []struct {
		name               string
		launchLevel        logrus.Level
		setLogLevelRequest *loggerv1.SetLogLevelRequest

		expectedErr      error
		expectedResponse *apitype.Logger
		expectedLogs     []spiretest.LogEntry
	}{
		{
			name:        "test SetLogger to FATAL on initialized to PANIC",
			launchLevel: logrus.PanicLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_FATAL,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_FATAL,
				LaunchLevel:  apitype.LogLevel_PANIC,
			},
			expectedLogs: nil,
		},
		{
			name:        "test SetLogger to INFO on initialized to PANIC",
			launchLevel: logrus.PanicLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_INFO,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_INFO,
				LaunchLevel:  apitype.LogLevel_PANIC,
			},
			// only the ending get logger will log
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test SetLogger to DEBUG on initialized to PANIC",
			launchLevel: logrus.PanicLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_DEBUG,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_DEBUG,
				LaunchLevel:  apitype.LogLevel_PANIC,
			},
			// only the ending get logger will log
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test SetLogger to PANIC on initialized to INFO",
			launchLevel: logrus.InfoLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_PANIC,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_PANIC,
				LaunchLevel:  apitype.LogLevel_INFO,
			},
			// the ending getlogger will be suppressed
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "panic",
					},
				},
			},
		},
		{
			name:        "test SetLogger to INFO on initialized to INFO",
			launchLevel: logrus.InfoLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_INFO,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_INFO,
				LaunchLevel:  apitype.LogLevel_INFO,
			},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test SetLogger to DEBUG on initialized to INFO",
			launchLevel: logrus.InfoLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_DEBUG,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_DEBUG,
				LaunchLevel:  apitype.LogLevel_INFO,
			},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "debug",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test SetLogger to PANIC on initialized to TRACE",
			launchLevel: logrus.TraceLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_PANIC,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_PANIC,
				LaunchLevel:  apitype.LogLevel_TRACE,
			},
			// the ending getlogger will be suppressed
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "trace",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "panic",
					},
				},
			},
		},
		{
			name:        "test SetLogger to INFO on initialized to TRACE",
			launchLevel: logrus.TraceLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_INFO,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_INFO,
				LaunchLevel:  apitype.LogLevel_TRACE,
			},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "trace",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test SetLogger to DEBUG on initialized to TRACE",
			launchLevel: logrus.TraceLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_DEBUG,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_DEBUG,
				LaunchLevel:  apitype.LogLevel_TRACE,
			},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "trace",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "debug",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, tt.launchLevel)
			defer test.Cleanup()

			resp, _ := test.client.SetLogLevel(context.Background(), tt.setLogLevelRequest)
			spiretest.RequireProtoEqual(t, resp, tt.expectedResponse)
			resp, err := test.client.GetLogger(context.Background(), &loggerv1.GetLoggerRequest{})
			require.Equal(t, err, tt.expectedErr)
			spiretest.RequireProtoEqual(t, resp, tt.expectedResponse)

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectedLogs)
		})
	}
}

// After changing the log level, gets the logger to check the log impact
// After resetting the log level, gets the logger to check the log impact
func TestResetLogger(t *testing.T) {
	for _, tt := range []struct {
		name               string
		launchLevel        logrus.Level
		setLogLevelRequest *loggerv1.SetLogLevelRequest

		expectedErr      error
		expectedResponse *apitype.Logger
		expectedLogs     []spiretest.LogEntry
	}{
		{
			name:        "test PANIC Logger set to FATAL then RESET",
			launchLevel: logrus.PanicLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_FATAL,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_PANIC,
				LaunchLevel:  apitype.LogLevel_PANIC,
			},
			expectedLogs: nil,
		},
		{
			name:        "test PANIC Logger set to INFO then RESET",
			launchLevel: logrus.PanicLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_INFO,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_PANIC,
				LaunchLevel:  apitype.LogLevel_PANIC,
			},
			// only the ending get logger will log
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "ResetLogLevel Called",
				},
			},
		},
		{
			name:        "test PANIC Logger set to DEBUG then RESET",
			launchLevel: logrus.PanicLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_DEBUG,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_PANIC,
				LaunchLevel:  apitype.LogLevel_PANIC,
			},
			// only the ending get logger will log
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "ResetLogLevel Called",
				},
			},
		},
		{
			name:        "test INFO Logger set to PANIC and then RESET",
			launchLevel: logrus.InfoLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_PANIC,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_INFO,
				LaunchLevel:  apitype.LogLevel_INFO,
			},
			// the ending getlogger will be suppressed
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "panic",
					},
				},
				// the second get, after the reset
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test INFO Logger set to INFO and then RESET",
			launchLevel: logrus.InfoLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_INFO,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_INFO,
				LaunchLevel:  apitype.LogLevel_INFO,
			},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "ResetLogLevel Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test INFO Logger set to DEBUG and then RESET",
			launchLevel: logrus.InfoLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_DEBUG,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_INFO,
				LaunchLevel:  apitype.LogLevel_INFO,
			},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "debug",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "ResetLogLevel Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test TRACE Logger set to PANIC and then RESET",
			launchLevel: logrus.TraceLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_PANIC,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_TRACE,
				LaunchLevel:  apitype.LogLevel_TRACE,
			},
			// the ending getlogger will be suppressed
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "trace",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "panic",
					},
				},
				// the second get logger, after the reset
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test TRACE Logger set to INFO and then RESET",
			launchLevel: logrus.TraceLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_INFO,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_TRACE,
				LaunchLevel:  apitype.LogLevel_TRACE,
			},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "trace",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "ResetLogLevel Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
		{
			name:        "test TRACE Logger set to DEBUG and then RESET",
			launchLevel: logrus.TraceLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_DEBUG,
			},

			expectedResponse: &apitype.Logger{
				CurrentLevel: apitype.LogLevel_TRACE,
				LaunchLevel:  apitype.LogLevel_TRACE,
			},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "trace",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						"NewLevel": "debug",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "ResetLogLevel Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "GetLogger Called",
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, tt.launchLevel)
			defer test.Cleanup()

			_, _ = test.client.SetLogLevel(context.Background(), tt.setLogLevelRequest)
			_, _ = test.client.GetLogger(context.Background(), &loggerv1.GetLoggerRequest{})
			resp, err := test.client.ResetLogLevel(context.Background(), &loggerv1.ResetLogLevelRequest{})

			require.Equal(t, err, tt.expectedErr)
			spiretest.RequireProtoEqual(t, resp, tt.expectedResponse)
			_, _ = test.client.GetLogger(context.Background(), &loggerv1.GetLoggerRequest{})
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectedLogs)
		})
	}
}

func TestUnsetSetLogLevelRequest(t *testing.T) {
	for _, tt := range []struct {
		name               string
		launchLevel        logrus.Level
		setLogLevelRequest *loggerv1.SetLogLevelRequest

		code             codes.Code
		expectedErr      string
		expectedResponse *apitype.Logger
		expectedLogs     []spiretest.LogEntry
	}{
		{
			name:               "test PANIC Logger set without a log level",
			launchLevel:        logrus.PanicLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{},

			code:             codes.Unknown,
			expectedErr:      "Invalid request, NewLevel value cannot be LogLevel_UNSPECIFIED",
			expectedResponse: nil,
			// the error seems to clear the log capture
			expectedLogs: nil,
		},
		{
			name:        "test PANIC Logger set to UNSPECIFIED",
			launchLevel: logrus.PanicLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_UNSPECIFIED,
			},

			code:             codes.Unknown,
			expectedErr:      "Invalid request, NewLevel value cannot be LogLevel_UNSPECIFIED",
			expectedResponse: nil,
			// the error seems to clear the log capture
			expectedLogs: nil,
		},
		{
			name:               "test INFO Logger set without a log level",
			launchLevel:        logrus.InfoLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{},

			code:             codes.Unknown,
			expectedErr:      "Invalid request, NewLevel value cannot be LogLevel_UNSPECIFIED",
			expectedResponse: nil,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "info",
					},
				},
			},
		},
		{
			name:        "test INFO Logger set to UNSPECIFIED",
			launchLevel: logrus.InfoLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_UNSPECIFIED,
			},

			code:             codes.Unknown,
			expectedErr:      "Invalid request, NewLevel value cannot be LogLevel_UNSPECIFIED",
			expectedResponse: nil,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "info",
					},
				},
			},
		},
		{
			name:               "test DEBUG Logger set without a log level",
			launchLevel:        logrus.DebugLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{},

			code:             codes.Unknown,
			expectedErr:      "Invalid request, NewLevel value cannot be LogLevel_UNSPECIFIED",
			expectedResponse: nil,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "debug",
					},
				},
			},
		},
		{
			name:        "test DEBUG Logger set to UNSPECIFIED",
			launchLevel: logrus.DebugLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_UNSPECIFIED,
			},

			code:             codes.Unknown,
			expectedErr:      "Invalid request, NewLevel value cannot be LogLevel_UNSPECIFIED",
			expectedResponse: nil,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Logger service configured",
					Data: logrus.Fields{
						"LaunchLevel": "debug",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, tt.launchLevel)
			defer test.Cleanup()

			resp, err := test.client.SetLogLevel(context.Background(), tt.setLogLevelRequest)
			spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.expectedErr)
			require.Nil(t, resp)

			spiretest.RequireProtoEqual(t, resp, tt.expectedResponse)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectedLogs)
		})
	}
}

type serviceTest struct {
	client loggerv1.LoggerClient
	done   func()

	logHook *test.Hook
}

func (s *serviceTest) Cleanup() {
	s.done()
}

func setupServiceTest(t *testing.T, launchLevel logrus.Level) *serviceTest {
	log, logHook := test.NewNullLogger()
	// logger level should initially match the launch level
	log.SetLevel(launchLevel)
	service := logger.New(logger.Config{
		Log:         log,
		LaunchLevel: launchLevel,
	})

	registerFn := func(s grpc.ServiceRegistrar) {
		logger.RegisterService(s, service)
	}
	overrideContext := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		return ctx
	}
	server := grpctest.StartServer(t, registerFn, grpctest.OverrideContext(overrideContext))
	conn := server.Dial(t)

	test := &serviceTest{
		done:    server.Stop,
		logHook: logHook,
		client:  loggerv1.NewLoggerClient(conn),
	}

	return test
}
