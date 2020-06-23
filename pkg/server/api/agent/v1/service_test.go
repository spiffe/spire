package agent_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
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

var agent1 = "spiffe://example.org/agent-1"
var agent2 = "spiffe://example.org/agent-2"
var agent3 = "spiffe://example.org/agent-3"

var testNodes map[string]*common.AttestedNode = map[string]*common.AttestedNode{
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
		CertSerialNumber:    "CertSerialNumber-2",
		NewCertSerialNumber: "CertSerialNumber-2",
		CertNotAfter:        2,
	},
	agent3: {
		SpiffeId:            agent3,
		AttestationDataType: "type-2",
		CertNotAfter:        3,
	},
}

var testNodeSelectors map[string]*datastore.NodeSelectors = map[string]*datastore.NodeSelectors{
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
	agent3: {
		SpiffeId: agent3,
		Selectors: []*common.Selector{
			{
				Type:  "node-selector-type-3",
				Value: "node-delector-value-3",
			},
		},
	},
}

var expectedAgents map[string]*types.Agent = map[string]*types.Agent{
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
	},
	agent3: {
		Id:                   &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-3"},
		AttestationType:      testNodes[agent3].AttestationDataType,
		X509SvidSerialNumber: testNodes[agent3].CertSerialNumber,
		X509SvidExpiresAt:    testNodes[agent3].CertNotAfter,
		Selectors: []*types.Selector{
			{
				Type:  testNodeSelectors[agent3].Selectors[0].Type,
				Value: testNodeSelectors[agent3].Selectors[0].Value,
			},
		},
		Banned: true,
	},
}

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
	ds := fakedatastore.New()
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

	ctx := context.Background()
	test.createTestNodes(ctx, t)

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
		name          string
		req           *agentpb.GetAgentRequest
		expectedAgent *types.Agent
		expectedCode  codes.Code
		err           string
		logMsg        string
		dsError       error
	}{
		{
			name:          "success 1",
			req:           &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-1"}},
			expectedAgent: expectedAgents[agent1],
		},
		{
			name:          "success 2",
			req:           &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-2"}},
			expectedAgent: expectedAgents[agent2],
		},
		{
			name:          "success 3",
			req:           &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-3"}},
			expectedAgent: expectedAgents[agent3],
		},
		{
			name: "success - with mask",
			req: &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-1"},
				OutputMask: &types.AgentMask{
					AttestationType:      true,
					X509SvidExpiresAt:    true,
					X509SvidSerialNumber: true,
				}},
			expectedAgent: &types.Agent{
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
			expectedAgent: &types.Agent{
				Id: expectedAgents[agent1].Id,
			},
		},
		{
			name:   "no SPIFFE ID",
			req:    &agentpb.GetAgentRequest{},
			logMsg: "Failed to parse SPIFFE ID",
			err:    "request must specify SPIFFE ID",
		},
		{
			name:   "invalid SPIFFE ID",
			req:    &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "invalid domain"}},
			logMsg: "Failed to parse SPIFFE ID",
			err:    `spiffeid: unable to parse: parse spiffe://invalid domain: invalid character " " in host name`,
		},
		{
			name:         "agent does not exist",
			req:          &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/does-not-exist"}},
			logMsg:       "Agent not found",
			err:          "agent not found",
			expectedCode: codes.NotFound,
		},
		{
			name:         "datastore error",
			req:          &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent-1"}},
			err:          "failed to fetch node: datastore error",
			expectedCode: codes.Internal,
			dsError:      errors.New("datastore error"),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			test.ds.SetError(tt.dsError)
			agent, err := test.client.GetAgent(context.Background(), tt.req)

			if tt.err != "" {
				require.Nil(t, agent)
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.err)
				require.Contains(t, test.logHook.LastEntry().Message, tt.logMsg)
				return
			}

			require.NoError(t, err)
			spiretest.AssertProtoEqual(t, tt.expectedAgent, agent)
		})
	}
}
