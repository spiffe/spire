package agent_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/agent/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	agentpb "github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	agent1 = "spiffe://example.org/agent-1"
	agent2 = "spiffe://example.org/agent-2"
)

var (
	ctx = context.Background()

	testNodes = map[string]*common.AttestedNode{
		agent1: {
			SpiffeId:            agent1,
			AttestationDataType: "type-1",
			CertSerialNumber:    "CertSerialNumber-1",
			NewCertSerialNumber: "CertSerialNumber-1",
			CertNotAfter:        1,
		},
		agent2: {
			SpiffeId:            agent2,
			AttestationDataType: "type-2",
			CertNotAfter:        3,
		},
	}

	testNodeSelectors = map[string]*datastore.NodeSelectors{
		agent1: {
			SpiffeId: agent1,
			Selectors: []*common.Selector{
				{
					Type:  "node-selector-type-1",
					Value: "node-delector-value-1",
				},
			},
		},
		agent2: {
			SpiffeId: agent2,
			Selectors: []*common.Selector{
				{
					Type:  "node-selector-type-2",
					Value: "node-delector-value-2",
				},
			},
		},
	}

	expectedAgents = map[string]*types.Agent{
		agent1: {
			Id:                   &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-1"},
			AttestationType:      testNodes[agent1].AttestationDataType,
			X509SvidSerialNumber: testNodes[agent1].CertSerialNumber,
			X509SvidExpiresAt:    testNodes[agent1].CertNotAfter,
			Selectors: []*types.Selector{
				{
					Type:  testNodeSelectors[agent1].Selectors[0].Type,
					Value: testNodeSelectors[agent1].Selectors[0].Value,
				},
			},
		},
		agent2: {
			Id:                   &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-2"},
			AttestationType:      testNodes[agent2].AttestationDataType,
			X509SvidSerialNumber: testNodes[agent2].CertSerialNumber,
			X509SvidExpiresAt:    testNodes[agent2].CertNotAfter,
			Selectors: []*types.Selector{
				{
					Type:  testNodeSelectors[agent2].Selectors[0].Type,
					Value: testNodeSelectors[agent2].Selectors[0].Value,
				},
			},
			Banned: true,
		},
	}
)

type serviceTest struct { //nolint: unused,deadcode
	client  agentpb.AgentClient
	done    func()
	ds      *fakedatastore.DataStore
	logHook *test.Hook
}

func (s *serviceTest) Cleanup() {
	s.done()
}

func setupServiceTest(t *testing.T) *serviceTest { //nolint: unused,deadcode
	ds := fakedatastore.New(t)
	service := agent.New(agent.Config{
		Datastore: ds,
	})

	log, logHook := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		agent.RegisterService(s, service)
	}

	test := &serviceTest{
		ds:      ds,
		logHook: logHook,
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)
	test.done = done
	test.client = agentpb.NewAgentClient(conn)

	return test
}

func (s *serviceTest) createTestNodes(ctx context.Context, t *testing.T) {
	for _, testNode := range testNodes {
		// create the test node
		_, err := s.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{Node: testNode})
		require.NoError(t, err)

		// set selectors to the test node
		_, err = s.ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{Selectors: testNodeSelectors[testNode.SpiffeId]})
		require.NoError(t, err)
	}
}

func TestGetAgent(t *testing.T) {
	for _, tt := range []struct {
		name    string
		req     *agentpb.GetAgentRequest
		agent   *types.Agent
		code    codes.Code
		err     string
		logs    []spiretest.LogEntry
		dsError error
	}{
		{
			name:  "success agent-1",
			req:   &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-1"}},
			agent: expectedAgents[agent1],
		},
		{
			name:  "success agent-2",
			req:   &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-2"}},
			agent: expectedAgents[agent2],
		},
		{
			name: "success - with mask",
			req: &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-1"},
				OutputMask: &types.AgentMask{
					AttestationType:      true,
					X509SvidExpiresAt:    true,
					X509SvidSerialNumber: true,
				}},
			agent: &types.Agent{
				Id:                   expectedAgents[agent1].Id,
				AttestationType:      expectedAgents[agent1].AttestationType,
				X509SvidExpiresAt:    expectedAgents[agent1].X509SvidExpiresAt,
				X509SvidSerialNumber: expectedAgents[agent1].X509SvidSerialNumber,
			},
		},
		{
			name: "success - with all false mask",
			req: &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-1"},
				OutputMask: &types.AgentMask{}},
			agent: &types.Agent{
				Id: expectedAgents[agent1].Id,
			},
		},
		{
			name: "no SPIFFE ID",
			req:  &agentpb.GetAgentRequest{},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to parse SPIFFE ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "request must specify SPIFFE ID",
					},
				},
			},
			err:  "request must specify SPIFFE ID",
			code: codes.InvalidArgument,
		},
		{
			name: "invalid SPIFFE ID",
			req:  &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "invalid domain"}},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to parse SPIFFE ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "spiffeid: unable to parse: parse spiffe://invalid domain: invalid character \" \" in host name",
					},
				},
			},
			err:  `spiffeid: unable to parse: parse spiffe://invalid domain: invalid character " " in host name`,
			code: codes.InvalidArgument,
		},
		{
			name: "agent does not exist",
			req:  &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/does-not-exist"}},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent not found",
					Data: logrus.Fields{
						telemetry.SPIFFEID: "spiffe://example.org/does-not-exist",
					},
				},
			},
			err:  "agent not found",
			code: codes.NotFound,
		},
		{
			name: "datastore error",
			req:  &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-1"}},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch node",
					Data: logrus.Fields{
						logrus.ErrorKey:    "datastore error",
						telemetry.SPIFFEID: "spiffe://example.org/agent-1",
					},
				},
			},
			err:     "failed to fetch node: datastore error",
			code:    codes.Internal,
			dsError: errors.New("datastore error"),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			test.createTestNodes(ctx, t)
			test.ds.SetNextError(tt.dsError)
			agent, err := test.client.GetAgent(context.Background(), tt.req)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.logs)
			if tt.err != "" {
				require.Nil(t, agent)
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.err)
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				return
			}

			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, tt.agent, agent)
		})
	}
}
