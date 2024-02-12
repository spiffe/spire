package logger_test

import (
	"context"
	"testing"
	"github.com/stretchr/testify/require"
	"github.com/spiffe/spire/test/spiretest"

	"bytes"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	"github.com/spiffe/spire/cmd/spire-server/cli/logger"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	commoncli "github.com/spiffe/spire/pkg/common/cli"

	"google.golang.org/grpc"
)

var availableFormats = []string{"pretty", "json"}

type loggerTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	args   []string
        server *fakeLoggerServer
	client cli.Command
}

func (l *loggerTest) afterTest(t *testing.T) {
	t.Logf("TEST:%s", t.Name())
	t.Logf("STDOUT:\n%s", l.stdout.String())
	t.Logf("STDIN:\n%s", l.stdin.String())
	t.Logf("STDERR:\n%s", l.stderr.String())
}

func TestGetHelp(t *testing.T) {
	for _, tt := range []struct{
		currentLevel       types.Logger_LogLevel
		defaultLevel       types.Logger_LogLevel
	}{
		{
			currentLevel: types.Logger_debug,
			defaultLevel: types.Logger_warn,
		},
		{
			currentLevel: types.Logger_panic,
			defaultLevel: types.Logger_trace,
		},
		{
			currentLevel: types.Logger_fatal,
			defaultLevel: types.Logger_error,
		},
		{
			currentLevel: types.Logger_info,
			defaultLevel: types.Logger_info,
		},
	}{
		server := &fakeLoggerServer{
			currentLevel: tt.currentLevel,
			defaultLevel: tt.defaultLevel,
		}
		test := setupTest(t, server, logger.NewGetCommandWithEnv)
		test.client.Help()
	
		require.Equal(t, getUsage, test.stderr.String())
	}
}

func TestGetSynopsis(t *testing.T) {
	cmd := logger.NewGetCommand()
	require.Equal(t, "Gets the logger details", cmd.Synopsis())
}

func TestGet(t *testing.T) {
	for _, tt := range []struct{
		name               string
                args               []string
		currentLevel       types.Logger_LogLevel
		defaultLevel       types.Logger_LogLevel
                expectReturnCode   int
                expectStdout       string
                expectStderr       string
                serverErr          error

	}{
		{
			name: "configured to info, set to info, using pretty output",
			args: []string{"-output", "pretty"},
			currentLevel: types.Logger_info,
			defaultLevel: types.Logger_info,
			expectReturnCode: 0,
			expectStdout: `Logger Level  : info
Logger Default: info

`,
		},
		{
			name: "configured to debug, set to warn, using pretty output",
			args: []string{"-output", "pretty"},
			currentLevel: types.Logger_warn,
			defaultLevel: types.Logger_debug,
			expectReturnCode: 0,
			expectStdout: `Logger Level  : warning
Logger Default: debug

`,
		},
		{
			name: "configured to error, set to trace, using pretty output",
			args: []string{"-output", "pretty"},
			currentLevel: types.Logger_trace,
			defaultLevel: types.Logger_error,
			expectReturnCode: 0,
			expectStdout: `Logger Level  : trace
Logger Default: error

`,
		},
		{
			name: "configured to panic, set to fatal, using pretty output",
			args: []string{"-output", "pretty"},
			currentLevel: types.Logger_fatal,
			defaultLevel: types.Logger_panic,
			expectReturnCode: 0,
			expectStdout: `Logger Level  : fatal
Logger Default: panic

`,
		},
		{
			name: "configured to info, set to info, using json output",
			args: []string{"-output", "json"},
			currentLevel: types.Logger_info,
			defaultLevel: types.Logger_info,
			expectReturnCode: 0,
			expectStdout: `{"current_level":"info","default_level":"info"}
`,
		},
		{
			name: "configured to debug, set to warn, using json output",
			args: []string{"-output", "json"},
			currentLevel: types.Logger_warn,
			defaultLevel: types.Logger_debug,
			expectReturnCode: 0,
			expectStdout: `{"current_level":"warn","default_level":"debug"}
`,
		},
		{
			name: "configured to error, set to trace, using json output",
			args: []string{"-output", "json"},
			currentLevel: types.Logger_trace,
			defaultLevel: types.Logger_error,
			expectReturnCode: 0,
			expectStdout: `{"current_level":"trace","default_level":"error"}
`,
		},
		{
			name: "configured to panic, set to fatal, using json output",
			args: []string{"-output", "json"},
			currentLevel: types.Logger_fatal,
			defaultLevel: types.Logger_panic,
			expectReturnCode: 0,
			expectStdout: `{"current_level":"fatal","default_level":"panic"}
`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := &fakeLoggerServer{
				currentLevel: tt.currentLevel,
				defaultLevel: tt.defaultLevel,
			}
			test := setupTest(t, server, logger.NewGetCommandWithEnv)
			test.server.err = tt.serverErr
			args := tt.args
			returnCode := test.client.Run(append(test.args, args...))
			require.Equal(t, tt.expectStdout, test.stdout.String())
			require.Equal(t, tt.expectStderr, test.stderr.String())
			require.Equal(t, tt.expectReturnCode, returnCode)
		})
	}
}

func setupTest(t *testing.T, server *fakeLoggerServer, newClient func(*commoncli.Env) cli.Command) *loggerTest {
	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		loggerv1.RegisterLoggerServer(s, server)
	})

	stdin  := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	client := newClient(&commoncli.Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})

	test := &loggerTest{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		args:   []string{common.AddrArg, common.GetAddr(addr)},
		server: server,
		client: client,
	}

	t.Cleanup(func() {
		test.afterTest(t)
	})

	return test
}

type fakeLoggerServer struct {
	loggerv1.UnimplementedLoggerServer

	currentLevel types.Logger_LogLevel
	defaultLevel types.Logger_LogLevel

	err error
}

func (s *fakeLoggerServer) GetLogger(_ context.Context, _ *loggerv1.GetLoggerRequest) (*types.Logger, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &types.Logger{
		CurrentLevel: s.currentLevel,
		DefaultLevel: s.defaultLevel,
	}, s.err
}

