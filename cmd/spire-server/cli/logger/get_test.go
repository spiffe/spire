package logger_test

import (
	"errors"
	"testing"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/cmd/spire-server/cli/logger"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

var (
	getUsage = `Usage of logger get:
  -output value
    	Desired output format (pretty, json); default: pretty.
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`
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
	for _, tt := range []struct{
		name               string
		// server state
                server             *mockLoggerServer
		// input
                args               []string
		// expected items
                expectReturnCode   int
                expectStdout       string
                expectStderr       string
	}{
		{
			name: "configured to info, set to info, using pretty output",
			args: []string{"-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_info,
					DefaultLevel: types.Logger_info,
				},
			},
			expectReturnCode: 0,
			expectStdout: `Logger Level  : info
Logger Default: info

`,
		},
		{
			name: "configured to debug, set to warn, using pretty output",
			args: []string{"-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_warn,
					DefaultLevel: types.Logger_debug,
				},
			},
			expectReturnCode: 0,
			expectStdout: `Logger Level  : warning
Logger Default: debug

`,
		},
		{
			name: "configured to error, set to trace, using pretty output",
			args: []string{"-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_trace,
					DefaultLevel: types.Logger_error,
				},
			},
			expectReturnCode: 0,
			expectStdout: `Logger Level  : trace
Logger Default: error

`,
		},
		{
			name: "configured to panic, set to fatal, using pretty output",
			args: []string{"-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_fatal,
					DefaultLevel: types.Logger_panic,
				},
			},
			expectReturnCode: 0,
			expectStdout: `Logger Level  : fatal
Logger Default: panic

`,
		},
		{
			name: "configured to info, set to info, using json output",
			args: []string{"-output", "json"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_info,
					DefaultLevel: types.Logger_info,
				},
			},
			expectReturnCode: 0,
			expectStdout: `{"current_level":"info","default_level":"info"}
`,
		},
		{
			name: "configured to debug, set to warn, using json output",
			args: []string{"-output", "json"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_warn,
					DefaultLevel: types.Logger_debug,
				},
			},
			expectReturnCode: 0,
			expectStdout: `{"current_level":"warn","default_level":"debug"}
`,
		},
		{
			name: "configured to error, set to trace, using json output",
			args: []string{"-output", "json"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_trace,
					DefaultLevel: types.Logger_error,
				},
			},
			expectReturnCode: 0,
			expectStdout: `{"current_level":"trace","default_level":"error"}
`,
		},
		{
			name: "configured to panic, set to fatal, using json output",
			args: []string{"-output", "json"},
			server: &mockLoggerServer{
				returnLogger: &types.Logger{
					CurrentLevel: types.Logger_fatal,
					DefaultLevel: types.Logger_panic,
				},
			},
			expectReturnCode: 0,
			expectStdout: `{"current_level":"fatal","default_level":"panic"}
`,
		},
		{
			name: "configured to info, set to info, server will error",
			args: []string{"-output", "pretty"},
			server: &mockLoggerServer{
				returnErr: errors.New("server is unavailable"),
			},
			expectReturnCode: 1,
			expectStderr: `Error: error fetching logger: rpc error: code = Unknown desc = server is unavailable
`,
		},
		{
			name: "bizzarro world, returns neither logger nor error",
			args: []string{"-output", "pretty"},
			server: &mockLoggerServer{
				returnLogger: nil,
			},
			expectReturnCode: 1,
			expectStderr: `Error: error fetching logger: rpc error: code = Internal desc = grpc: error while marshaling: proto: Marshal called with nil
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
