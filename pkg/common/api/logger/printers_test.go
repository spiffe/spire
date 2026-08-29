package logger_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/api/logger"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/stretchr/testify/require"
)

type errorWriter struct {
	ReturnError error
	buf         strings.Builder
}

var _ io.Writer = &errorWriter{}

func (e *errorWriter) Write(p []byte) (n int, err error) {
	if e.ReturnError != nil {
		return 0, e.ReturnError
	}
	return e.buf.Write(p)
}

func (e *errorWriter) String() string {
	return e.buf.String()
}

func TestPrettyPrintLogger(t *testing.T) {
	for _, tt := range []struct {
		name           string
		logger         any
		outWriter      errorWriter
		errWriter      errorWriter
		env            *commoncli.Env
		expectedStdout string
		expectedStderr string
		expectedError  error
	}{
		{
			name: "pretty print debug/info",
			logger: &types.Logger{
				CurrentLevel: types.LogLevel_DEBUG,
				LaunchLevel:  types.LogLevel_INFO,
			},
			expectedStdout: "Logger Level : debug\nLaunch Level : info\n\n",
		},
		{
			name: "writer error",
			outWriter: errorWriter{
				ReturnError: errors.New("cannot write"),
			},
			logger: &types.Logger{
				CurrentLevel: types.LogLevel_DEBUG,
				LaunchLevel:  types.LogLevel_INFO,
			},
			expectedError: errors.New("cannot write"),
		},
		{
			name: "wrong proto type",
			outWriter: errorWriter{
				ReturnError: errors.New("cannot write"),
			},
			logger:        &types.Entry{},
			expectedError: errors.New("internal error: unexpected type *types.Entry returned; please report this as a bug"),
		},
	} {
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
