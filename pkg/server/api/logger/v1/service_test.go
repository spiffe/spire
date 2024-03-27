package logger_test

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	apitype "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/logger/v1"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/test/grpctest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func TestGetLogger(t *testing.T) {
	for _, tt := range []struct {
		name        string
		launchLevel logrus.Level

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
					Message: "GetLogger Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
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
					Message: "GetLogger Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
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
					Message: "GetLogger Called",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, tt.launchLevel)
			defer test.Cleanup()

			resp, err := test.client.GetLogger(context.Background(), &loggerv1.GetLoggerRequest{})
			require.NoError(t, err)
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
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "INFO",
						telemetry.Status:      "success",
						telemetry.Type:        "audit",
					},
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
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "DEBUG",
						telemetry.Status:      "success",
						telemetry.Type:        "audit",
					},
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
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "panic",
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
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "INFO",
						telemetry.Status:      "success",
						telemetry.Type:        "audit",
					},
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
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "debug",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "DEBUG",
						telemetry.Status:      "success",
						telemetry.Type:        "audit",
					},
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
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "panic",
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
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "INFO",
						telemetry.Status:      "success",
						telemetry.Type:        "audit",
					},
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
					Message: "SetLogLevel Called",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "debug",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.NewLogLevel: "DEBUG",
						telemetry.Status:      "success",
						telemetry.Type:        "audit",
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
			require.NoError(t, err)
			spiretest.RequireProtoEqual(t, resp, tt.expectedResponse)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectedLogs)

			// Verify using get
			getResp, err := test.client.GetLogger(context.Background(), &loggerv1.GetLoggerRequest{})
			require.Equal(t, err, tt.expectedErr)
			spiretest.RequireProtoEqual(t, getResp, tt.expectedResponse)
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
					Message: "ResetLogLevel Called",
					Data: logrus.Fields{
						telemetry.LaunchLogLevel: "panic",
					},
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
					Message: "ResetLogLevel Called",
					Data: logrus.Fields{
						telemetry.LaunchLogLevel: "panic",
					},
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
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
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
					Message: "ResetLogLevel Called",
					Data: logrus.Fields{
						telemetry.LaunchLogLevel: "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
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
					Message: "ResetLogLevel Called",
					Data: logrus.Fields{
						telemetry.LaunchLogLevel: "info",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
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
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
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
					Message: "ResetLogLevel Called",
					Data: logrus.Fields{
						telemetry.LaunchLogLevel: "trace",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
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
					Message: "ResetLogLevel Called",
					Data: logrus.Fields{
						telemetry.LaunchLogLevel: "trace",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, tt.launchLevel)
			defer test.Cleanup()

			_, err := test.client.SetLogLevel(context.Background(), tt.setLogLevelRequest)
			require.NoError(t, err)
			// Remove logs before calling reset
			test.logHook.Reset()

			// Call Reset
			resp, err := test.client.ResetLogLevel(context.Background(), &loggerv1.ResetLogLevelRequest{})
			require.NoError(t, err)

			spiretest.RequireProtoEqual(t, resp, tt.expectedResponse)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectedLogs)

			// Verify it was really updated
			getResp, err := test.client.GetLogger(context.Background(), &loggerv1.GetLoggerRequest{})
			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, tt.expectedResponse, getResp)
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
			name:               "logger no set without a log level",
			launchLevel:        logrus.DebugLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{},

			code:             codes.InvalidArgument,
			expectedErr:      "newLevel value cannot be LogLevel_UNSPECIFIED",
			expectedResponse: nil,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: newLevel value cannot be LogLevel_UNSPECIFIED",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.NewLogLevel:   "UNSPECIFIED",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "newLevel value cannot be LogLevel_UNSPECIFIED",
					},
				},
			},
		},
		{
			name:        "logger no set to UNSPECIFIED",
			launchLevel: logrus.DebugLevel,
			setLogLevelRequest: &loggerv1.SetLogLevelRequest{
				NewLevel: apitype.LogLevel_UNSPECIFIED,
			},

			code:             codes.InvalidArgument,
			expectedErr:      "newLevel value cannot be LogLevel_UNSPECIFIED",
			expectedResponse: nil,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: newLevel value cannot be LogLevel_UNSPECIFIED",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.NewLogLevel:   "UNSPECIFIED",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "newLevel value cannot be LogLevel_UNSPECIFIED",
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
		Log: log,
	})

	registerFn := func(s grpc.ServiceRegistrar) {
		logger.RegisterService(s, service)
	}
	overrideContext := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		return ctx
	}
	server := grpctest.StartServer(t, registerFn,
		grpctest.OverrideContext(overrideContext),
		grpctest.Middleware(middleware.WithAuditLog(false)))
	conn := server.Dial(t)
	// Remove configuration logs
	logHook.Reset()

	test := &serviceTest{
		done:    server.Stop,
		logHook: logHook,
		client:  loggerv1.NewLoggerClient(conn),
	}

	return test
}
