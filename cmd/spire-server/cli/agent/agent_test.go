package agent_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/mitchellh/cli"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/cli/agent"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	availableFormats = []string{"pretty", "json"}
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
	require.Equal(t, banUsage, test.stderr.String())
}

func TestBan(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectReturnCode   int
		expectStdoutPretty string
		expectStdoutJSON   string
		expectStderr       string
		serverErr          error
	}{
		{
			name:               "success",
			args:               []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectReturnCode:   0,
			expectStdoutPretty: "Agent banned successfully\n",
			expectStdoutJSON:   "{}",
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
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, agent.NewBanCommandWithEnv)
				test.server.err = tt.serverErr
				args := tt.args
				args = append(args, "-output", format)

				returnCode := test.client.Run(append(test.args, args...))

				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectStdoutPretty, tt.expectStdoutJSON)
				require.Equal(t, tt.expectStderr, test.stderr.String())
				require.Equal(t, tt.expectReturnCode, returnCode)
			})
		}
	}
}

func TestEvictHelp(t *testing.T) {
	test := setupTest(t, agent.NewEvictCommandWithEnv)

	test.client.Help()
	require.Equal(t, evictUsage, test.stderr.String())
}

func TestEvict(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		args                 []string
		expectedReturnCode   int
		expectedStdoutPretty string
		expectedStdoutJSON   string
		expectedStderr       string
		serverErr            error
	}{
		{
			name:                 "success",
			args:                 []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectedReturnCode:   0,
			expectedStdoutPretty: "Agent evicted successfully\n",
			expectedStdoutJSON:   "{}",
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
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, agent.NewEvictCommandWithEnv)
				test.server.err = tt.serverErr
				args := tt.args
				args = append(args, "-output", format)

				returnCode := test.client.Run(append(test.args, args...))

				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
				require.Equal(t, tt.expectedStderr, test.stderr.String())
				require.Equal(t, tt.expectedReturnCode, returnCode)
			})
		}
	}
}

func TestCountHelp(t *testing.T) {
	test := setupTest(t, agent.NewCountCommandWithEnv)

	test.client.Help()
	require.Equal(t, countUsage, test.stderr.String())
}

func TestCount(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		args                 []string
		expectedReturnCode   int
		expectedStdoutPretty string
		expectedStdoutJSON   string
		expectedStderr       string
		existentAgents       []*types.Agent
		serverErr            error
	}{
		{
			name:                 "0 agents",
			expectedReturnCode:   0,
			expectedStdoutPretty: "0 attested agents",
			expectedStdoutJSON:   `{"count":0}`,
		},
		{
			name:                 "count 1 agent",
			expectedReturnCode:   0,
			expectedStdoutPretty: "1 attested agent",
			expectedStdoutJSON:   `{"count":1}`,
			existentAgents:       testAgents,
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
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, agent.NewCountCommandWithEnv)
				test.server.agents = tt.existentAgents
				test.server.err = tt.serverErr
				args := tt.args
				args = append(args, "-output", format)

				returnCode := test.client.Run(append(test.args, args...))

				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
				require.Equal(t, tt.expectedStderr, test.stderr.String())
				require.Equal(t, tt.expectedReturnCode, returnCode)
			})
		}
	}
}

func TestListHelp(t *testing.T) {
	test := setupTest(t, agent.NewListCommandWithEnv)

	test.client.Help()
	require.Equal(t, listUsage, test.stderr.String())
}

func TestList(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		args                 []string
		expectedReturnCode   int
		expectedStdoutPretty string
		expectedStdoutJSON   string
		expectedStderr       string
		expectReq            *agentv1.ListAgentsRequest
		existentAgents       []*types.Agent
		expectedFormat       string
		serverErr            error
	}{
		{
			name:                 "1 agent",
			expectedReturnCode:   0,
			existentAgents:       testAgents,
			expectedStdoutPretty: "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
			expectedStdoutJSON:   `{"agents":[{"id":{"trust_domain":"example.org","path":"/spire/agent/agent1"},"attestation_type":"","x509svid_serial_number":"","x509svid_expires_at":"0","selectors":[],"banned":false}],"next_page_token":""}`,
			expectReq: &agentv1.ListAgentsRequest{
				Filter:   &agentv1.ListAgentsRequest_Filter{},
				PageSize: 1000,
			},
		},
		{
			name:               "no agents",
			expectedReturnCode: 0,
			expectedStdoutJSON: `{"agents":[],"next_page_token":""}`,
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
			existentAgents:       testAgents,
			expectedStdoutPretty: "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
			expectedStdoutJSON:   `{"agents":[{"id":{"trust_domain":"example.org","path":"/spire/agent/agent1"},"attestation_type":"","x509svid_serial_number":"","x509svid_expires_at":"0","selectors":[],"banned":false}],"next_page_token":""}`,
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
			existentAgents:       testAgents,
			expectedStdoutPretty: "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
			expectedStdoutJSON:   `{"agents":[{"id":{"trust_domain":"example.org","path":"/spire/agent/agent1"},"attestation_type":"","x509svid_serial_number":"","x509svid_expires_at":"0","selectors":[],"banned":false}],"next_page_token":""}`,
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
			existentAgents:       testAgents,
			expectedStdoutPretty: "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
			expectedStdoutJSON:   `{"agents":[{"id":{"trust_domain":"example.org","path":"/spire/agent/agent1"},"attestation_type":"","x509svid_serial_number":"","x509svid_expires_at":"0","selectors":[],"banned":false}],"next_page_token":""}`,
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
			existentAgents:       testAgents,
			expectedStdoutPretty: "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
			expectedStdoutJSON:   `{"agents":[{"id":{"trust_domain":"example.org","path":"/spire/agent/agent1"},"attestation_type":"","x509svid_serial_number":"","x509svid_expires_at":"0","selectors":[],"banned":false}],"next_page_token":""}`,
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
			existentAgents:       testAgents,
			expectedStdoutPretty: "Found 1 attested agent:\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
			expectedStdoutJSON:   `{"agents":[{"id":{"trust_domain":"example.org","path":"/spire/agent/agent1"},"attestation_type":"","x509svid_serial_number":"","x509svid_expires_at":"0","selectors":[],"banned":false}],"next_page_token":""}`,
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
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, agent.NewListCommandWithEnv)
				test.server.agents = tt.existentAgents
				test.server.err = tt.serverErr
				args := tt.args
				args = append(args, "-output", format)

				returnCode := test.client.Run(append(test.args, args...))

				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
				spiretest.RequireProtoEqual(t, tt.expectReq, test.server.gotListAgentRequest)
				require.Equal(t, tt.expectedStderr, test.stderr.String())
				require.Equal(t, tt.expectedReturnCode, returnCode)
			})
		}
	}
}

func TestShowHelp(t *testing.T) {
	test := setupTest(t, agent.NewShowCommandWithEnv)

	test.client.Help()
	require.Equal(t, showUsage, test.stderr.String())
}

func TestShow(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		args                 []string
		expectedReturnCode   int
		expectedStdoutPretty string
		expectedStdoutJSON   string
		expectedStderr       string
		existentAgents       []*types.Agent
		serverErr            error
	}{
		{
			name:                 "success",
			args:                 []string{"-spiffeID", "spiffe://example.org/spire/agent/agent1"},
			expectedReturnCode:   0,
			existentAgents:       testAgents,
			expectedStdoutPretty: "Found an attested agent given its SPIFFE ID\n\nSPIFFE ID         : spiffe://example.org/spire/agent/agent1",
			expectedStdoutJSON:   `{"id":{"trust_domain":"example.org","path":"/spire/agent/agent1"},"attestation_type":"","x509svid_serial_number":"","x509svid_expires_at":"0","selectors":[],"banned":false}`,
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
			name:                 "show selectors",
			args:                 []string{"-spiffeID", "spiffe://example.org/spire/agent/agent2"},
			existentAgents:       testAgentsWithSelectors,
			expectedReturnCode:   0,
			expectedStdoutPretty: "Selectors         : k8s_psat:agent_ns:spire\nSelectors         : k8s_psat:agent_sa:spire-agent\nSelectors         : k8s_psat:cluster:demo-cluster",
			expectedStdoutJSON:   `{"id":{"trust_domain":"example.org","path":"/spire/agent/agent2"},"attestation_type":"","x509svid_serial_number":"","x509svid_expires_at":"0","selectors":[{"type":"k8s_psat","value":"agent_ns:spire"},{"type":"k8s_psat","value":"agent_sa:spire-agent"},{"type":"k8s_psat","value":"cluster:demo-cluster"}],"banned":false}`,
		},
		{
			name:                 "show banned",
			args:                 []string{"-spiffeID", "spiffe://example.org/spire/agent/banned"},
			existentAgents:       testAgentsWithBanned,
			expectedReturnCode:   0,
			expectedStdoutPretty: "Banned            : true",
			expectedStdoutJSON:   `{"id":{"trust_domain":"example.org","path":"/spire/agent/banned"},"attestation_type":"","x509svid_serial_number":"","x509svid_expires_at":"0","selectors":[],"banned":true}`,
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, agent.NewShowCommandWithEnv)
				test.server.err = tt.serverErr
				test.server.agents = tt.existentAgents
				args := tt.args
				args = append(args, "-output", format)

				returnCode := test.client.Run(append(test.args, args...))

				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectedStdoutPretty, tt.expectedStdoutJSON)
				require.Equal(t, tt.expectedStderr, test.stderr.String())
				require.Equal(t, tt.expectedReturnCode, returnCode)
			})
		}
	}
}

func setupTest(t *testing.T, newClient func(*commoncli.Env) cli.Command) *agentTest {
	server := &fakeAgentServer{}

	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		agentv1.RegisterAgentServer(s, server)
	})

	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	client := newClient(&commoncli.Env{
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
