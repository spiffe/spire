package logger_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/cli/logger"
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
	for _, tt := range []struct {
		name string
		// service state
		service *mockLoggerService
		// input
		args []string
		// expected items
		expectedSetValue types.LogLevel
		expectReturnCode int
		expectStdout     string
		expectStderr     string
	}{
		{
			name: "set to debug, configured to info, using pretty output",
			args: []string{"-level", "debug", "-output", "pretty"},
			service: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_DEBUG,
					LaunchLevel:  types.LogLevel_INFO,
				},
			},
			expectedSetValue: types.LogLevel_DEBUG,
			expectReturnCode: 0,
			expectStdout: `Logger Level : debug
Launch Level : info

`,
		},
		{
			name: "set to warn, configured to debug, using pretty output",
			args: []string{"-level", "warn", "-output", "pretty"},
			service: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_WARN,
					LaunchLevel:  types.LogLevel_DEBUG,
				},
			},
			expectedSetValue: types.LogLevel_WARN,
			expectReturnCode: 0,
			expectStdout: `Logger Level : warning
Launch Level : debug

`,
		},
		{
			name: "set to panic, configured to fatal, using pretty output",
			args: []string{"-level", "panic", "-output", "pretty"},
			service: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_PANIC,
					LaunchLevel:  types.LogLevel_FATAL,
				},
			},
			expectedSetValue: types.LogLevel_PANIC,
			expectReturnCode: 0,
			expectStdout: `Logger Level : panic
Launch Level : fatal

`,
		},
		{
			name: "set with invalid setting of never, logger unadjusted from (info,info)",
			args: []string{"-level", "never", "-output", "pretty"},
			service: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_INFO,
					LaunchLevel:  types.LogLevel_INFO,
				},
			},
			expectReturnCode: 1,
			expectStderr: `Error: the value "never" is not a valid setting
`,
		},
		{
			name: "No attribute set, cli returns error",
			args: []string{"-output", "pretty"},
			service: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_INFO,
					LaunchLevel:  types.LogLevel_INFO,
				},
			},
			expectReturnCode: 1,
			expectStderr: `Error: a value (-level) must be set
`,
		},
		{
			name: "bizzarro world, set to trace, logger unadjusted from (info,info)",
			args: []string{"-level", "trace", "-output", "pretty"},
			service: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_INFO,
					LaunchLevel:  types.LogLevel_INFO,
				},
			},
			expectedSetValue: types.LogLevel_TRACE,
			expectReturnCode: 0,
			expectStdout: `Logger Level : info
Launch Level : info

`,
		},
		{
			name: "service failed to set",
			args: []string{"-level", "trace", "-output", "pretty"},
			service: &mockLoggerService{
				returnErr: status.Error(codes.Internal, "oh no"),
			},
			expectReturnCode: 1,
			expectStderr: `Error: failed to set log level: rpc error: code = Internal desc = oh no
`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupCliTest(t, tt.service, logger.NewSetCommandWithEnv)
			returnCode := test.client.Run(append(test.args, tt.args...))
			require.Equal(t, tt.expectReturnCode, returnCode)
			require.Equal(t, tt.expectStderr, test.stderr.String())
			require.Equal(t, tt.expectStdout, test.stdout.String())
		})
	}
}
