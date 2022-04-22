package agent_test

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/mitchellh/cli"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/cli/agent"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	testAgents = []*types.Agent{
		{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent1"}},
	}
	testAgentsWithBanned = []*types.Agent{
		{
			Id:     &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/banned"},
			Banned: true,
		},
	}
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

func TestBanHelp(t *testing.T) {
	test := setupTest(t, agent.NewBanCommandWithEnv)

	test.client.Help()
	require.Equal(t, `Usage of agent ban:`+common.AddrUsage+
		`  -spiffeID string
    	The SPIFFE ID of the agent to ban (agent identity)
`, test.stderr.String())
}

func TestBan(t *testing.T) {
	for _, tt := range []struct {
		name             string
		args             []string
		expectReturnCode int
		expectStdout     string
		expectStderr     string
		serverErr        error
	}{
		{
			name:             "success",
			args:             []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectReturnCode: 0,
			expectStdout:     "Agent banned successfully\n",
		},
		{
			name:             "no spiffe id",
			expectReturnCode: 1,
			expectStderr:     "Error: a SPIFFE ID is required\n",
		},
		{
			name:             "wrong UDS path",
			args:             []string{common.AddrArg, common.AddrValue},
			expectReturnCode: 1,
			expectStderr:     common.AddrError,
		},
		{
			name:             "server error",
			args:             []string{"-spiffeID", "spiffe://example.org/spire/agent/foo"},
			serverErr:        status.Error(codes.Internal, "internal server error"),
			expectReturnCode: 1,
			expectStderr:     "Error: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, agent.NewBanCommandWithEnv)
			test.server.err = tt.serverErr

			returnCode := test.client.Run(append(test.args, tt.args...))
			require.Equal(t, tt.expectStdout, test.stdout.String())
			require.Equal(t, tt.expectStderr, test.stderr.String())
			require.Equal(t, tt.expectReturnCode, returnCode)
		})
	}
}

func TestEvictHelp(t *testing.T) {
	test := setupTest(t, agent.NewEvictCommandWithEnv)

	test.client.Help()
	require.Equal(t, `Usage of agent evict:`+common.AddrUsage+
		`  -spiffeID string
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
			args:               []string{common.AddrArg, common.AddrValue},
			expectedReturnCode: 1,
			expectedStderr:     common.AddrError,
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
	require.Equal(t, `Usage of agent count:`+common.AddrUsage, test.stderr.String())
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
			args:               []string{common.AddrArg, common.AddrValue},
			expectedReturnCode: 1,
			expectedStderr:     common.AddrError,
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
	require.Equal(t, listUsage, test.stderr.String())
}

func TestList(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectedReturnCode int
		expectedStdout     string
		expectedStderr     string
		expectReq          *agentv1.ListAgentsRequest
		existentAgents     []*types.Agent
		serverErr          error
	}{
		{
			name:               "1 agent",
			expectedReturnCode: 0,
			existentAgents:     testAgents,
			expectedStdout:     "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
			expectReq: &agentv1.ListAgentsRequest{
				Filter:   &agentv1.ListAgentsRequest_Filter{},
				PageSize: 1000,
			},
		},
		{
			name:               "no agents",
			expectedReturnCode: 0,
			expectReq: &agentv1.ListAgentsRequest{
				Filter:   &agentv1.ListAgentsRequest_Filter{},
				PageSize: 1000,
			},
		},
		{
			name:               "server error",
			expectedReturnCode: 1,
			serverErr:          status.Error(codes.Internal, "internal server error"),
			expectedStderr:     "Error: rpc error: code = Internal desc = internal server error\n",
			expectReq: &agentv1.ListAgentsRequest{
				Filter:   &agentv1.ListAgentsRequest_Filter{},
				PageSize: 1000,
			},
		},
		{
			name: "by selector: default matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz"},
			expectReq: &agentv1.ListAgentsRequest{
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_SUPERSET,
					},
				},
				PageSize: 1000,
			},
			existentAgents: testAgents,
			expectedStdout: "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
		},
		{
			name: "by selector: any matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "any"},
			expectReq: &agentv1.ListAgentsRequest{
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_ANY,
					},
				},
				PageSize: 1000,
			},
			existentAgents: testAgents,
			expectedStdout: "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
		},
		{
			name: "by selector: exact matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "exact"},
			expectReq: &agentv1.ListAgentsRequest{
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_EXACT,
					},
				},
				PageSize: 1000,
			},
			existentAgents: testAgents,
			expectedStdout: "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
		},
		{
			name: "by selector: superset matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "superset"},
			expectReq: &agentv1.ListAgentsRequest{
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_SUPERSET,
					},
				},
				PageSize: 1000,
			},
			existentAgents: testAgents,
			expectedStdout: "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
		},
		{
			name: "by selector: subset matcher",
			args: []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "subset"},
			expectReq: &agentv1.ListAgentsRequest{
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "foo", Value: "bar"},
							{Type: "bar", Value: "baz"},
						},
						Match: types.SelectorMatch_MATCH_SUBSET,
					},
				},
				PageSize: 1000,
			},
			existentAgents: testAgents,
			expectedStdout: "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
		},
		{
			name:               "List by selectors: Invalid matcher",
			args:               []string{"-selector", "foo:bar", "-selector", "bar:baz", "-matchSelectorsOn", "NO-MATCHER"},
			expectedReturnCode: 1,
			expectedStderr:     "Error: unsupported match behavior\n",
		},
		{
			name:               "List by selector using invalid selector",
			args:               []string{"-selector", "invalid-selector"},
			expectedReturnCode: 1,
			expectedStderr:     "Error: error parsing selector \"invalid-selector\": selector \"invalid-selector\" must be formatted as type:value\n",
		},
		{
			name:               "wrong UDS path",
			args:               []string{common.AddrArg, common.AddrValue},
			expectedReturnCode: 1,
			expectedStderr:     common.AddrError,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupTest(t, agent.NewListCommandWithEnv)
			test.server.agents = tt.existentAgents
			test.server.err = tt.serverErr
			returnCode := test.client.Run(append(test.args, tt.args...))

			spiretest.RequireProtoEqual(t, tt.expectReq, test.server.gotListAgentRequest)
			require.Contains(t, test.stdout.String(), tt.expectedStdout)
			require.Equal(t, tt.expectedStderr, test.stderr.String())
			require.Equal(t, tt.expectedReturnCode, returnCode)
		})
	}
}

func TestShowHelp(t *testing.T) {
	test := setupTest(t, agent.NewShowCommandWithEnv)

	test.client.Help()
	require.Equal(t, `Usage of agent show:`+common.AddrUsage+
		`  -spiffeID string
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
			args:               []string{common.AddrArg, common.AddrValue},
			expectedReturnCode: 1,
			expectedStderr:     common.AddrError,
		},
		{
			name:               "show selectors",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent2"},
			existentAgents:     testAgentsWithSelectors,
			expectedReturnCode: 0,
			expectedStdout:     "Selectors         : k8s_psat:agent_ns:spire\nSelectors         : k8s_psat:agent_sa:spire-agent\nSelectors         : k8s_psat:cluster:demo-cluster",
		},
		{
			name:               "show banned",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/banned"},
			existentAgents:     testAgentsWithBanned,
			expectedReturnCode: 0,
			expectedStdout:     "Banned            : true",
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

	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		agentv1.RegisterAgentServer(s, server)
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
		args:   []string{common.AddrArg, common.GetAddr(addr)},
		server: server,
		client: client,
	}

	t.Cleanup(func() {
		test.afterTest(t)
	})

	return test
}

type fakeAgentServer struct {
	agentv1.UnimplementedAgentServer

	agents              []*types.Agent
	gotListAgentRequest *agentv1.ListAgentsRequest
	err                 error
}

func (s *fakeAgentServer) BanAgent(ctx context.Context, req *agentv1.BanAgentRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.err
}

func (s *fakeAgentServer) DeleteAgent(ctx context.Context, req *agentv1.DeleteAgentRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, s.err
}

func (s *fakeAgentServer) CountAgents(ctx context.Context, req *agentv1.CountAgentsRequest) (*agentv1.CountAgentsResponse, error) {
	return &agentv1.CountAgentsResponse{
		Count: int32(len(s.agents)),
	}, s.err
}

func (s *fakeAgentServer) ListAgents(ctx context.Context, req *agentv1.ListAgentsRequest) (*agentv1.ListAgentsResponse, error) {
	s.gotListAgentRequest = req
	return &agentv1.ListAgentsResponse{
		Agents: s.agents,
	}, s.err
}

func (s *fakeAgentServer) GetAgent(ctx context.Context, req *agentv1.GetAgentRequest) (*types.Agent, error) {
	if len(s.agents) > 0 {
		return s.agents[0], s.err
	}

	return nil, s.err
}
