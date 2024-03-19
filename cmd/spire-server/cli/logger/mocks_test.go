package logger_test

import (
	"io"
	"testing"

	"github.com/spiffe/spire/test/spiretest"

	"bytes"
	"context"

	"github.com/mitchellh/cli"
	loggerv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/logger/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"google.golang.org/grpc"
)

// an input/output capture struct
type loggerTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	args   []string
	server *mockLoggerService
	client cli.Command
}

// serialization of capture
func (l *loggerTest) afterTest(t *testing.T) {
	t.Logf("TEST:%s", t.Name())
	t.Logf("STDOUT:\n%s", l.stdout.String())
	t.Logf("STDIN:\n%s", l.stdin.String())
	t.Logf("STDERR:\n%s", l.stderr.String())
}

// setup of input/output capture
func setupCliTest(t *testing.T, server *mockLoggerService, newClient func(*commoncli.Env) cli.Command) *loggerTest {
	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		loggerv1.RegisterLoggerServer(s, server)
	})

	stdin := new(bytes.Buffer)
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

// a mock grpc logger server
type mockLoggerService struct {
	loggerv1.UnimplementedLoggerServer

	receivedSetValue *types.LogLevel
	returnLogger     *types.Logger
	returnErr        error
}

// mock implementation for GetLogger
func (s *mockLoggerService) GetLogger(context.Context, *loggerv1.GetLoggerRequest) (*types.Logger, error) {
	return s.returnLogger, s.returnErr
}

func (s *mockLoggerService) SetLogLevel(_ context.Context, req *loggerv1.SetLogLevelRequest) (*types.Logger, error) {
	s.receivedSetValue = &req.NewLevel
	return s.returnLogger, s.returnErr
}

func (s *mockLoggerService) ResetLogLevel(context.Context, *loggerv1.ResetLogLevelRequest) (*types.Logger, error) {
	s.receivedSetValue = nil
	return s.returnLogger, s.returnErr
}

var _ io.Writer = &errorWriter{}

type errorWriter struct {
	ReturnError error
	Buffer      bytes.Buffer
}

func (e *errorWriter) Write(p []byte) (n int, err error) {
	if e.ReturnError != nil {
		return 0, e.ReturnError
	}
	return e.Buffer.Write(p)
}

func (e *errorWriter) String() string {
	return e.Buffer.String()
}
