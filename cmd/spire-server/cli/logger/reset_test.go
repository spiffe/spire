package logger_test

import (
	"testing"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/cli/logger"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestResetHelp(t *testing.T) {
	test := setupCliTest(t, nil, logger.NewResetCommandWithEnv)
	test.client.Help()
	require.Equal(t, "", test.stdout.String())
	require.Equal(t, resetUsage, test.stderr.String())
}

func TestResetSynopsis(t *testing.T) {
	cmd := logger.NewResetCommand()
	require.Equal(t, "Reset the logger details to launch level", cmd.Synopsis())
}

func TestReset(t *testing.T) {
	for _, tt := range []struct {
		name    string
		args    []string
		service *mockLoggerService

		expectReturnCode int
		expectStdout     string
		expectStderr     string
	}{
		{
			name: "reset successfully",
			args: []string{"-output", "pretty"},
			service: &mockLoggerService{
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
			name: "service failed",
			args: []string{"-output", "pretty"},
			service: &mockLoggerService{
				returnErr: status.Error(codes.Internal, "oh no"),
			},
			expectReturnCode: 1,
			expectStderr: `Error: failed to reset logger: rpc error: code = Internal desc = oh no
`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupCliTest(t, tt.service, logger.NewResetCommandWithEnv)
			returnCode := test.client.Run(append(test.args, tt.args...))
			require.Equal(t, tt.expectReturnCode, returnCode)
			require.Equal(t, tt.expectStderr, test.stderr.String())
			require.Equal(t, tt.expectStdout, test.stdout.String())
		})
	}
}
