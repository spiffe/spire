package agent_test

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mitchellh/cli"
	"github.com/spiffe/spire/cmd/spire-server/cli/agent"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	agentpb "github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	testAgents              = []*types.Agent{{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent1"}}}
	testAgentsWithSelectors = []*types.Agent{
		{
			Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent2"},
			Selectors: []*types.Selector{
				{Type: "k8s_psat", Value: "agent_ns:spire"},
				{Type: "k8s_psat", Value: "agent_sa:spire-agent"},
				{Type: "k8s_psat", Value: "cluster:demo-cluster"},
			},
		},
	}
)

type agentTest struct {
	stdin  *bytes.Buffer
	stdout *bytes.Buffer
	stderr *bytes.Buffer

	args   []string
	server *fakeAgentServer

	client cli.Command
}

func (s *agentTest) afterTest(t *testing.T) {
	t.Logf("TEST:%s", t.Name())
	t.Logf("STDOUT:\n%s", s.stdout.String())
	t.Logf("STDIN:\n%s", s.stdin.String())
	t.Logf("STDERR:\n%s", s.stderr.String())
}

func TestEvictHelp(t *testing.T) {
	test := setupTest(t, agent.NewEvictCommandWithEnv)

	test.client.Help()
	require.Equal(t, `Usage of agent evict:
  -registrationUDSPath string
    	Path to the SPIRE Server API socket (deprecated; use -socketPath)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID of the agent to evict (agent identity)
`, test.stderr.String())
}

func TestEvict(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectedReturnCode int
		expectedStdout     string
		expectedStderr     string
		serverErr          error
	}{
		{
			name:               "success",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectedReturnCode: 0,
			expectedStdout:     "Agent evicted successfully\n",
		},

		{
			name:               "no spiffe id",
			expectedReturnCode: 1,
			expectedStderr:     "Error: a SPIFFE ID is required\n",
		},
		{
			name:               "wrong UDS path",
			args:               []string{"-socketPath", "does-not-exist.sock"},
			expectedReturnCode: 1,
			expectedStderr:     "Error: connection error: desc = \"transport: error while dialing: dial unix does-not-exist.sock: connect: no such file or directory\"\n",
		},
		{
			name:               "server error",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/foo"},
			serverErr:          status.Error(codes.Internal, "internal server error"),
			expectedReturnCode: 1,
			expectedStderr:     "Error: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, agent.NewEvictCommandWithEnv)
			test.server.err = tt.serverErr

			returnCode := test.client.Run(append(test.args, tt.args...))
			require.Equal(t, tt.expectedStdout, test.stdout.String())
			require.Equal(t, tt.expectedStderr, test.stderr.String())
			require.Equal(t, tt.expectedReturnCode, returnCode)
		})
	}
}

func TestCountHelp(t *testing.T) {
	test := setupTest(t, agent.NewCountCommandWithEnv)

	test.client.Help()
	require.Equal(t, `Usage of agent count:
  -registrationUDSPath string
    	Path to the SPIRE Server API socket (deprecated; use -socketPath)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`, test.stderr.String())
}

func TestCount(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectedReturnCode int
		expectedStdout     string
		expectedStderr     string
		existentAgents     []*types.Agent
		serverErr          error
	}{
		{
			name:               "0 agents",
			expectedReturnCode: 0,
			expectedStdout:     "0 attested agents",
		},
		{
			name:               "count 1 agent",
			expectedReturnCode: 0,
			expectedStdout:     "1 attested agent",
			existentAgents:     testAgents,
		},
		{
			name:               "server error",
			expectedReturnCode: 1,
			serverErr:          status.Error(codes.Internal, "internal server error"),
			expectedStderr:     "Error: rpc error: code = Internal desc = internal server error\n",
		},
		{
			name:               "wrong UDS path",
			args:               []string{"-socketPath", "does-not-exist.sock"},
			expectedReturnCode: 1,
			expectedStderr:     "Error: connection error: desc = \"transport: error while dialing: dial unix does-not-exist.sock: connect: no such file or directory\"\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, agent.NewCountCommandWithEnv)
			test.server.agents = tt.existentAgents
			test.server.err = tt.serverErr
			returnCode := test.client.Run(append(test.args, tt.args...))
			require.Contains(t, test.stdout.String(), tt.expectedStdout)
			require.Equal(t, tt.expectedStderr, test.stderr.String())
			require.Equal(t, tt.expectedReturnCode, returnCode)
		})
	}
}

func TestListHelp(t *testing.T) {
	test := setupTest(t, agent.NewListCommandWithEnv)

	test.client.Help()
	require.Equal(t, `Usage of agent list:
  -registrationUDSPath string
    	Path to the SPIRE Server API socket (deprecated; use -socketPath)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
`, test.stderr.String())
}

func TestList(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectedReturnCode int
		expectedStdout     string
		expectedStderr     string
		existentAgents     []*types.Agent
		serverErr          error
	}{
		{
			name:               "1 agent",
			expectedReturnCode: 0,
			existentAgents:     testAgents,
			expectedStdout:     "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
		},
		{
			name:               "no agents",
			expectedReturnCode: 0,
		},
		{
			name:               "server error",
			expectedReturnCode: 1,
			serverErr:          status.Error(codes.Internal, "internal server error"),
			expectedStderr:     "Error: rpc error: code = Internal desc = internal server error\n",
		},
		{
			name:               "wrong UDS path",
			args:               []string{"-socketPath", "does-not-exist.sock"},
			expectedReturnCode: 1,
			expectedStderr:     "Error: connection error: desc = \"transport: error while dialing: dial unix does-not-exist.sock: connect: no such file or directory\"\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, agent.NewListCommandWithEnv)
			test.server.agents = tt.existentAgents
			test.server.err = tt.serverErr
			returnCode := test.client.Run(append(test.args, tt.args...))
			require.Contains(t, test.stdout.String(), tt.expectedStdout)
			require.Equal(t, tt.expectedStderr, test.stderr.String())
			require.Equal(t, tt.expectedReturnCode, returnCode)
		})
	}
}

func TestShowHelp(t *testing.T) {
	test := setupTest(t, agent.NewShowCommandWithEnv)

	test.client.Help()
	require.Equal(t, `Usage of agent show:
  -registrationUDSPath string
    	Path to the SPIRE Server API socket (deprecated; use -socketPath)
  -socketPath string
    	Path to the SPIRE Server API socket (default "/tmp/spire-server/private/api.sock")
  -spiffeID string
    	The SPIFFE ID of the agent to show (agent identity)
`, test.stderr.String())
}

func TestShow(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectedReturnCode int
		expectedStdout     string
		expectedStderr     string
		existentAgents     []*types.Agent
		serverErr          error
	}{
		{
			name:               "success",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectedReturnCode: 0,
			existentAgents:     testAgents,
			expectedStdout:     "Found an attested agent given its SPIFFE ID\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
		},
		{
			name:               "no spiffe id",
			expectedReturnCode: 1,
			expectedStderr:     "Error: a SPIFFE ID is required\n",
		},
		{
			name:               "show error",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			existentAgents:     testAgents,
			expectedReturnCode: 1,
			serverErr:          status.Error(codes.Internal, "internal server error"),
			expectedStderr:     "Error: rpc error: code = Internal desc = internal server error\n",
		},
		{
			name:               "wrong UDS path",
			args:               []string{"-socketPath", "does-not-exist.sock"},
			expectedReturnCode: 1,
			expectedStderr:     "Error: connection error: desc = \"transport: error while dialing: dial unix does-not-exist.sock: connect: no such file or directory\"\n",
		},
		{
			name:               "show selectors",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent2"},
			existentAgents:     testAgentsWithSelectors,
			expectedReturnCode: 0,
			expectedStdout:     "Selectors         : k8s_psat:agent_ns:spire\nSelectors         : k8s_psat:agent_sa:spire-agent\nSelectors         : k8s_psat:cluster:demo-cluster",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, agent.NewShowCommandWithEnv)
			test.server.err = tt.serverErr
			test.server.agents = tt.existentAgents

			returnCode := test.client.Run(append(test.args, tt.args...))
			require.Contains(t, test.stdout.String(), tt.expectedStdout)
			require.Equal(t, tt.expectedStderr, test.stderr.String())
			require.Equal(t, tt.expectedReturnCode, returnCode)
		})
	}
}

func setupTest(t *testing.T, newClient func(*common_cli.Env) cli.Command) *agentTest {
	server := &fakeAgentServer{}

	socketPath := spiretest.StartGRPCSocketServerOnTempSocket(t, func(s *grpc.Server) {
		agentpb.RegisterAgentServer(s, server)
	})

	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	client := newClient(&common_cli.Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})

	test := &agentTest{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		args:   []string{"-socketPath", socketPath},
		server: server,
		client: client,
	}

	t.Cleanup(func() {
		test.afterTest(t)
	})

	return test
}

type fakeAgentServer struct {
	agentpb.UnimplementedAgentServer

	agents []*types.Agent
	err    error
}

func (s *fakeAgentServer) DeleteAgent(ctx context.Context, req *agentpb.DeleteAgentRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.err
}

func (s *fakeAgentServer) CountAgents(ctx context.Context, req *agentpb.CountAgentsRequest) (*agentpb.CountAgentsResponse, error) {
	return &agentpb.CountAgentsResponse{
		Count: int32(len(s.agents)),
	}, s.err
}

func (s *fakeAgentServer) ListAgents(ctx context.Context, req *agentpb.ListAgentsRequest) (*agentpb.ListAgentsResponse, error) {
	return &agentpb.ListAgentsResponse{
		Agents: s.agents,
	}, s.err
}

func (s *fakeAgentServer) GetAgent(ctx context.Context, req *agentpb.GetAgentRequest) (*types.Agent, error) {
	if len(s.agents) > 0 {
		return s.agents[0], s.err
	}

	return nil, s.err
}
