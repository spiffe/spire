package token

import (
	"bytes"
	"testing"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSynopsis(t *testing.T) {
	require.Equal(t, "Generates a join token", NewGenerateCommand().Synopsis())
}

func TestCreateToken(t *testing.T) {
	for _, tt := range []struct {
		name string

		args           []string
		token          string
		expectedStderr string
		expectedStdout string
		expectedReq    *agent.CreateJoinTokenRequest
		serverErr      error
	}{
		{
			name: "create token",
			args: []string{
				"-spiffeID", "spiffe://example.org/agent",
				"-ttl", "1200",
			},
			expectedReq: &agent.CreateJoinTokenRequest{
				AgentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
				Ttl:     1200,
			},
			expectedStdout: "Token: token\n",
			token:          "token",
		},
		{
			name:           "without spiffe ID",
			expectedStdout: "Token: token\nWarning: Missing SPIFFE ID.\n",
			expectedReq: &agent.CreateJoinTokenRequest{
				Ttl: 600,
			},
			token: "token",
		},
		{
			name: "malformed spiffe ID",
			args: []string{
				"-spiffeID", "invalid id",
			},
			expectedStderr: "Error: spiffeid: invalid scheme\n",
		},
		{
			name: "server fails to create token",
			args: []string{
				"-spiffeID", "spiffe://example.org/agent",
			},
			expectedReq: &agent.CreateJoinTokenRequest{
				AgentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
				Ttl:     600,
			},
			token:          "token",
			expectedStderr: "Error: rpc error: code = Internal desc = server error\n",
			serverErr:      status.New(codes.Internal, "server error").Err(),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t)
			args := append(test.args, tt.args...)
			test.server.token = tt.token
			test.server.expectReq = tt.expectedReq
			test.server.err = tt.serverErr

			rc := test.client.Run(args)
			if tt.expectedStderr != "" {
				require.Equal(t, tt.expectedStderr, test.stderr.String())
				require.Equal(t, 1, rc)
				return
			}

			require.Empty(t, test.stderr.String())
			require.Equal(t, 0, rc)
			require.Equal(t, tt.expectedStdout, test.stdout.String())
		})
	}
}

type tokenTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	args   []string
	server *fakeAgentServer

	client cli.Command
}

func setupTest(t *testing.T) *tokenTest {
	server := &fakeAgentServer{t: t}

	socketPath := spiretest.StartGRPCSocketServerOnTempSocket(t, func(s *grpc.Server) {
		agent.RegisterAgentServer(s, server)
	})

	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	client := newGenerateCommand(&common_cli.Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})

	return &tokenTest{
		stderr: stderr,
		stdin:  stdin,
		stdout: stdout,
		args:   []string{"-socketPath", socketPath},
		server: server,
		client: client,
	}
}

type fakeAgentServer struct {
	agent.AgentServer

	t         testing.TB
	expectReq *agent.CreateJoinTokenRequest
	err       error
	token     string
}

func (f *fakeAgentServer) CreateJoinToken(ctx context.Context, req *agent.CreateJoinTokenRequest) (*types.JoinToken, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.AssertProtoEqual(f.t, f.expectReq, req)

	return &types.JoinToken{
		Value: f.token,
	}, nil
}
