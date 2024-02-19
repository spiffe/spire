package logger_test

import (
	"testing"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/cmd/spire-server/cli/logger"
	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

var (
	setUsage = `Usage of logger set:
  -level string
    	The new log level, one of (panic, fatal, error, warn, info, debug, trace, default)
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
)

func TestSetHelp(t *testing.T) {
	test := setupCliTest(t, nil, logger.NewSetCommandWithEnv)
	test.client.Help()
	require.Equal(t, "", test.stdout.String())
	require.Equal(t, setUsage, test.stderr.String())
}

func TestSetSynopsis(t *testing.T) {
	cmd := logger.NewSetCommand()
	require.Equal(t, "Sets the logger details", cmd.Synopsis())
}

func TestSet(t *testing.T) {
	for _, tt := range []struct{
		name               string
		// server state
                server             *mockLoggerServer
		// input
                args               []string
		// expected items
		expectedSetValue   loggerv1.SetLogLevelRequest_SetValue
                expectReturnCode   int
                expectStdout       string
                expectStderr       string
	}{
		{
			name: "set to debug, configured to info, using pretty output",
			args: []string{"-level", "debug", "-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_debug,
					DefaultLevel: types.Logger_info,
				},
			},
			expectedSetValue: loggerv1.SetLogLevelRequest_DEBUG,
			expectReturnCode: 0,
			expectStdout: `Logger Level  : debug
Logger Default: info

`,
		},
		{
			name: "set to warn, configured to debug, using pretty output",
			args: []string{"-level", "warn", "-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_warn,
					DefaultLevel: types.Logger_debug,
				},
			},
			expectedSetValue: loggerv1.SetLogLevelRequest_WARN,
			expectReturnCode: 0,
			expectStdout: `Logger Level  : warning
Logger Default: debug

`,
		},
		{
			name: "set to default, configured to error, using pretty output",
			args: []string{"-level", "default", "-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_error,
					DefaultLevel: types.Logger_error,
				},
			},
			expectedSetValue: loggerv1.SetLogLevelRequest_DEFAULT,
			expectReturnCode: 0,
			expectStdout: `Logger Level  : error
Logger Default: error

`,
		},
		{
			name: "set to panic, configured to fatal, using pretty output",
			args: []string{"-level", "panic", "-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_panic,
					DefaultLevel: types.Logger_fatal,
				},
			},
			expectedSetValue: loggerv1.SetLogLevelRequest_PANIC,
			expectReturnCode: 0,
			expectStdout: `Logger Level  : panic
Logger Default: fatal

`,
		},
		{
			name: "set with invalid setting of never, logger unadjusted from (info,info)",
			args: []string{"-level", "never", "-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_info,
					DefaultLevel: types.Logger_info,
				},
			},
			expectedSetValue: loggerv1.SetLogLevelRequest_TRACE,
			expectReturnCode: 1,
			expectStderr: `Error: the value never is not a valid setting
`,
		},
		{
			name: "bizzarro world, returns neither logger nor error",
			args: []string{"-level", "info", "-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: nil,
			},
			expectReturnCode: 1,
			expectStderr: `Error: error fetching logger: rpc error: code = Internal desc = grpc: error while marshaling: proto: Marshal called with nil
`,
		},
		{
			name: "No attribute set, cli returns error",
			args: []string{"-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_info,
					DefaultLevel: types.Logger_info,
				},
			},
			expectReturnCode: 1,
			expectStderr: `Error: a value (-level) must be set
`,
		},
		{
			name: "bizzarro world, set to trace, logger unadjusted from (info,info)",
			args: []string{"-level", "trace", "-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_info,
					DefaultLevel: types.Logger_info,
				},
			},
			expectedSetValue: loggerv1.SetLogLevelRequest_TRACE,
			expectReturnCode: 0,
			expectStdout: `Logger Level  : info
Logger Default: info

`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupCliTest(t, tt.server, logger.NewSetCommandWithEnv)
			returnCode := test.client.Run(append(test.args, tt.args...))
			require.Equal(t, tt.expectStdout, test.stdout.String())
			require.Equal(t, tt.expectStderr, test.stderr.String())
			require.Equal(t, tt.expectReturnCode, returnCode)
		})
	}
}
