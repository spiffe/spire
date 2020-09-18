package agent

import (
	"testing"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gotest.tools/assert"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/spiffe/spire/proto/spire/api/server/agent/v1"

	"github.com/spiffe/spire/test/spiretest"
)

func TestEvict(t *testing.T) {
	server := &evictServer{}

	socketPath := spiretest.StartGRPCSocketServerOnTempSocket(t, func(s *grpc.Server) {
		agent.RegisterAgentServer(s, server)
	})

	for _, tt := range []struct {
		name         string
		args         []string
		evictErr     error
		expectedCode int
	}{
		{
			name:         "missing SPIFFE ID",
			args:         []string{},
			expectedCode: 1,
		},
		{
			name:         "empty UDS path",
			args:         []string{"-registrationUDSPath", ""},
			expectedCode: 1,
		},
		{
			name:         "bad UDS path",
			args:         []string{"-registrationUDSPath", "does-not-exist.sock", "-spiffeID", "spiffe://example.org/spire/agent/foo"},
			expectedCode: 1,
		},
		{
			name:         "malformed ID",
			args:         []string{"-spiffeID", "bad ID"},
			expectedCode: 1,
		},
		{
			name:         "not an agent ID",
			args:         []string{"-spiffeID", "spiffe://example.org/workload"},
			expectedCode: 1,
		},
		{
			name:         "failed to evict",
			args:         []string{"-spiffeID", "spiffe://example.org/spire/agent/foo"},
			evictErr:     status.Error(codes.NotFound, "agent not found"),
			expectedCode: 1,
		},
		{
			name: "success",
			args: []string{"-spiffeID", "spiffe://example.org/spire/agent/foo"},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			server.evictErr = tt.evictErr

			cli := EvictCLI{}
			args := append([]string{"-registrationUDSPath", socketPath}, tt.args...)
			code := cli.Run(args)
			assert.Equal(t, code, tt.expectedCode, "command did not exit with the expected code")
		})
	}
}

type evictServer struct {
	agent.UnimplementedAgentServer

	evictErr error
}

func (s *evictServer) DeleteAgent(ctx context.Context, req *agent.DeleteAgentRequest) (*empty.Empty, error) {
	return &empty.Empty{}, s.evictErr
}
