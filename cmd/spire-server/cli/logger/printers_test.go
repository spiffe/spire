package logger_test

import (
	"errors"
	"testing"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/cmd/spire-server/cli/logger"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
)

func TestPrettyPrintLogger(t *testing.T) {
	for _, tt := range []struct {
		name string
		logger interface{}
		outWriter errorWriter
		errWriter errorWriter
		env *commoncli.Env
		expectedStdout string
		expectedStderr string
		expectedError error
	}{
		{
			name: "test",
			logger: &types.Logger{
				CurrentLevel: types.Logger_debug,
				DefaultLevel: types.Logger_info,
			},
			expectedStdout: `Logger Level  : debug
Logger Default: info

`,
		},
		{
			name: "test env returning an error",
			outWriter: errorWriter{
				ReturnError: errors.New("cannot write"),
			},
			logger: &types.Logger{
				CurrentLevel: types.Logger_debug,
				DefaultLevel: types.Logger_info,
			},
			expectedError: errors.New("cannot write"),
		},
		{
			name: "test nil logger",
			outWriter: errorWriter{
				ReturnError: errors.New("cannot write"),
			},
			logger: &types.Entry{
			},
			expectedError: errors.New("internal error: logger not found; please report this as a bug"),
		},
	}{
		t.Run(tt.name, func(t *testing.T) {
			tt.env = &commoncli.Env{
				Stdout: &tt.outWriter,
				Stderr: &tt.errWriter,
			}
			require.Equal(t, logger.PrettyPrintLogger(tt.env, tt.logger), tt.expectedError)
			require.Equal(t, tt.outWriter.String(), tt.expectedStdout)
			require.Equal(t, tt.errWriter.String(), tt.expectedStderr)
		})
	}
	
}

