package token

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/mitchellh/cli"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var availableFormats = []string{"pretty", "json"}

func TestSynopsis(t *testing.T) {
	require.Equal(t, "Generates a join token", NewGenerateCommand().Synopsis())
}

func TestCreateToken(t *testing.T) {
	for _, tt := range []struct {
		name string

		args                 []string
		token                string
		expectedStderr       string
		expectedStdoutPretty string
		expectedStdoutJSON   string
		expectedReq          *agentv1.CreateJoinTokenRequest
		serverErr            error
	}{
		{
			name: "create token",
			args: []string{
				"-spiffeID", "spiffe://example.org/agent",
				"-ttl", "1200",
			},
			expectedReq: &agentv1.CreateJoinTokenRequest{
				AgentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
				Ttl:     1200,
			},
			expectedStdoutPretty: "Token: token\n",
			expectedStdoutJSON:   `{"value":"token","expires_at":"0"}`,
			token:                "token",
		},
		{
			name:                 "without spiffe ID",
			expectedStdoutPretty: "Token: token\nWarning: Missing SPIFFE ID.\n",
			expectedStdoutJSON:   `{"value":"token","expires_at":"0"}`,
			expectedReq: &agentv1.CreateJoinTokenRequest{
				Ttl: 600,
			},
			token: "token",
		},
		{
			name: "malformed spiffe ID",
			args: []string{
				"-spiffeID", "invalid id",
			},
			expectedStderr: "Error: scheme is missing or invalid\n",
		},
		{
			name: "server fails to create token",
			args: []string{
				"-spiffeID", "spiffe://example.org/agent",
			},
			expectedReq: &agentv1.CreateJoinTokenRequest{
				AgentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
				Ttl:     600,
			},
			token:          "token",
			expectedStderr: "Error: rpc error: code = Internal desc = server error\n",
			serverErr:      status.New(codes.Internal, "server error").Err(),
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t)
				test.server.token = tt.token
				test.server.expectReq = tt.expectedReq
				test.server.err = tt.serverErr
				args := tt.args
				args = append(args, "-output", format)

				rc := test.client.Run(test.args(args...))
				if tt.expectedStderr != "" {
					require.Equal(t, tt.expectedStderr, test.stderr.String())
					require.Equal(t, 1, rc)
					return
				}

				require.Empty(t, test.stderr.String())
				require.Equal(t, 0, rc)
				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
			})
		}
	}
}

type tokenTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	addr   string
	server *fakeAgentServer

	client cli.Command
}

func (t *tokenTest) args(extra ...string) []string {
	return append([]string{common.AddrArg, t.addr}, extra...)
}

func setupTest(t *testing.T) *tokenTest {
	server := &fakeAgentServer{t: t}

	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		agentv1.RegisterAgentServer(s, server)
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
		addr:   common.GetAddr(addr),
		stderr: stderr,
		stdin:  stdin,
		stdout: stdout,
		server: server,
		client: client,
	}
}

type fakeAgentServer struct {
	agentv1.AgentServer

	t         testing.TB
	expectReq *agentv1.CreateJoinTokenRequest
	err       error
	token     string
}

func (f *fakeAgentServer) CreateJoinToken(_ context.Context, req *agentv1.CreateJoinTokenRequest) (*types.JoinToken, error) {
	if f.err != nil {
		return nil, f.err
	}
	spiretest.AssertProtoEqual(f.t, f.expectReq, req)

	return &types.JoinToken{
		Value: f.token,
	}, nil
}

func requireOutputBasedOnFormat(t *testing.T, format, stdoutString string, expectedStdoutPretty, expectedStdoutJSON string) {
	switch format {
	case "pretty":
		require.Contains(t, stdoutString, expectedStdoutPretty)
	case "json":
		if expectedStdoutJSON != "" {
			require.JSONEq(t, expectedStdoutJSON, stdoutString)
		} else {
			require.Empty(t, stdoutString)
		}
	}
}
