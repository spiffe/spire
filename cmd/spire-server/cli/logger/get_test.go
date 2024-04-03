package logger_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/cli/logger"
)

func TestGetHelp(t *testing.T) {
	test := setupCliTest(t, nil, logger.NewGetCommandWithEnv)
	test.client.Help()
	require.Equal(t, "", test.stdout.String())
	require.Equal(t, getUsage, test.stderr.String())
}

func TestGetSynopsis(t *testing.T) {
	cmd := logger.NewGetCommand()
	require.Equal(t, "Gets the logger details", cmd.Synopsis())
}

func TestGet(t *testing.T) {
	for _, tt := range []struct {
		name string
		// server state
		server *mockLoggerService
		// input
		args []string
		// expected items
		expectReturnCode int
		expectStdout     string
		expectStderr     string
	}{
		{
			name: "configured to info, set to info, using pretty output",
			args: []string{"-output", "pretty"},
			server: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_INFO,
					LaunchLevel:  types.LogLevel_INFO,
				},
			},
			expectReturnCode: 0,
			expectStdout: `Logger Level : info
Launch Level : info

`,
		},
		{
			name: "configured to debug, set to warn, using pretty output",
			args: []string{"-output", "pretty"},
			server: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_WARN,
					LaunchLevel:  types.LogLevel_DEBUG,
				},
			},
			expectReturnCode: 0,
			expectStdout: `Logger Level : warning
Launch Level : debug

`,
		},
		{
			name: "configured to error, set to trace, using pretty output",
			args: []string{"-output", "pretty"},
			server: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_TRACE,
					LaunchLevel:  types.LogLevel_ERROR,
				},
			},
			expectReturnCode: 0,
			expectStdout: `Logger Level : trace
Launch Level : error

`,
		},
		{
			name: "configured to panic, set to fatal, using pretty output",
			args: []string{"-output", "pretty"},
			server: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_FATAL,
					LaunchLevel:  types.LogLevel_PANIC,
				},
			},
			expectReturnCode: 0,
			expectStdout: `Logger Level : fatal
Launch Level : panic

`,
		},
		{
			name: "configured to info, set to info, using json output",
			args: []string{"-output", "json"},
			server: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_INFO,
					LaunchLevel:  types.LogLevel_INFO,
				},
			},
			expectReturnCode: 0,
			expectStdout: `{"current_level":"INFO","launch_level":"INFO"}
`,
		},
		{
			name: "configured to debug, set to warn, using json output",
			args: []string{"-output", "json"},
			server: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_WARN,
					LaunchLevel:  types.LogLevel_DEBUG,
				},
			},
			expectReturnCode: 0,
			expectStdout: `{"current_level":"WARN","launch_level":"DEBUG"}
`,
		},
		{
			name: "configured to error, set to trace, using json output",
			args: []string{"-output", "json"},
			server: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_TRACE,
					LaunchLevel:  types.LogLevel_ERROR,
				},
			},
			expectReturnCode: 0,
			expectStdout: `{"current_level":"TRACE","launch_level":"ERROR"}
`,
		},
		{
			name: "configured to panic, set to fatal, using json output",
			args: []string{"-output", "json"},
			server: &mockLoggerService{
				returnLogger: &types.Logger{
					CurrentLevel: types.LogLevel_FATAL,
					LaunchLevel:  types.LogLevel_PANIC,
				},
			},
			expectReturnCode: 0,
			expectStdout: `{"current_level":"FATAL","launch_level":"PANIC"}
`,
		},
		{
			name: "configured to info, set to info, server will error",
			args: []string{"-output", "pretty"},
			server: &mockLoggerService{
				returnErr: errors.New("server is unavailable"),
			},
			expectReturnCode: 1,
			expectStderr: `Error: error fetching logger: rpc error: code = Unknown desc = server is unavailable
`,
		},
		{
			name: "bizzarro world, returns neither logger nor error",
			args: []string{"-output", "pretty"},
			server: &mockLoggerService{
				returnLogger: nil,
			},
			expectReturnCode: 1,
			expectStderr: `Error: internal error: returned current log level is undefined; please report this as a bug
`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupCliTest(t, tt.server, logger.NewGetCommandWithEnv)
			returnCode := test.client.Run(append(test.args, tt.args...))
			require.Equal(t, tt.expectStdout, test.stdout.String())
			require.Equal(t, tt.expectStderr, test.stderr.String())
			require.Equal(t, tt.expectReturnCode, returnCode)
		})
	}
}
