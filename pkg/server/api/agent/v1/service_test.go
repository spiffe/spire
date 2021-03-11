package agent_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/agent/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	agentpb "github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakenoderesolver"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeservernodeattestor"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"gotest.tools/assert"
)

const (
	agent1 = "spiffe://example.org/spire/agent/agent-1"
	agent2 = "spiffe://example.org/spire/agent/agent-2"
)

var (
	ctx     = context.Background()
	td      = spiffeid.RequireTrustDomainFromString("example.org")
	agentID = td.NewID("agent")

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
					Value: "node-selector-value-1",
				},
			},
		},
		agent2: {
			SpiffeId: agent2,
			Selectors: []*common.Selector{
				{
					Type:  "node-selector-type-2",
					Value: "node-selector-value-2",
				},
			},
		},
	}

	expectedAgents = map[string]*types.Agent{
		agent1: {
			Id:                   &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-1"},
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
			Id:                   &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-2"},
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

func TestCountAgents(t *testing.T) {
	ids := []spiffeid.ID{
		spiffeid.Must("example.org", "node1"),
		spiffeid.Must("example.org", "node2"),
		spiffeid.Must("example.org", "node3"),
	}

	for _, tt := range []struct {
		name       string
		count      int32
		resp       *agentpb.CountAgentsResponse
		code       codes.Code
		dsError    error
		err        string
		expectLogs []spiretest.LogEntry
	}{
		{
			name:  "0 nodes",
			count: 0,
			resp:  &agentpb.CountAgentsResponse{Count: 0},
		},
		{
			name:  "1 node",
			count: 1,
			resp:  &agentpb.CountAgentsResponse{Count: 1},
		},
		{
			name:  "2 nodes",
			count: 2,
			resp:  &agentpb.CountAgentsResponse{Count: 2},
		},
		{
			name:  "3 nodes",
			count: 3,
			resp:  &agentpb.CountAgentsResponse{Count: 3},
		},
		{
			name:    "ds error",
			code:    codes.Internal,
			dsError: status.Error(codes.Internal, "some error"),
			err:     "failed to count agents: some error",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to count agents",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = some error",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			for i := 0; i < int(tt.count); i++ {
				_, err := test.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
					Node: &common.AttestedNode{
						SpiffeId:            ids[i].String(),
						AttestationDataType: "t1",
						CertSerialNumber:    "badcafe",
						CertNotAfter:        time.Now().Add(-time.Minute).Unix(),
						NewCertNotAfter:     time.Now().Add(time.Minute).Unix(),
						NewCertSerialNumber: "new badcafe",
						Selectors: []*common.Selector{
							{Type: "a", Value: "1"},
							{Type: "b", Value: "2"},
						},
					},
				})
				require.NoError(t, err)
			}

			test.ds.SetNextError(tt.dsError)
			resp, err := test.client.CountAgents(ctx, &agentpb.CountAgentsRequest{})

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			spiretest.AssertProtoEqual(t, tt.resp, resp)
		})
	}
}

func TestListAgents(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	notAfter := time.Now().Add(-time.Minute).Unix()
	newNoAfter := time.Now().Add(time.Minute).Unix()
	node1ID := spiffeid.Must("example.org", "node1")
	node1 := &common.AttestedNode{
		SpiffeId:            node1ID.String(),
		AttestationDataType: "t1",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        notAfter,
		NewCertNotAfter:     newNoAfter,
		NewCertSerialNumber: "new badcafe",
		Selectors: []*common.Selector{
			{Type: "a", Value: "1"},
			{Type: "b", Value: "2"},
		},
	}
	_, err := test.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
		Node: node1,
	})
	require.NoError(t, err)
	_, err = test.ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  node1.SpiffeId,
			Selectors: node1.Selectors},
	})
	require.NoError(t, err)

	node2ID := spiffeid.Must("example.org", "node2")
	node2 := &common.AttestedNode{
		SpiffeId:            node2ID.String(),
		AttestationDataType: "t2",
		CertSerialNumber:    "deadbeef",
		CertNotAfter:        notAfter,
		NewCertNotAfter:     newNoAfter,
		NewCertSerialNumber: "new deadbeef",
		Selectors: []*common.Selector{
			{Type: "a", Value: "1"},
			{Type: "c", Value: "3"},
		},
	}
	_, err = test.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
		Node: node2,
	})
	require.NoError(t, err)
	_, err = test.ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  node2.SpiffeId,
			Selectors: node2.Selectors},
	})
	require.NoError(t, err)

	node3ID := spiffeid.Must("example.org", "node3")
	node3 := &common.AttestedNode{
		SpiffeId:            node3ID.String(),
		AttestationDataType: "t3",
		CertSerialNumber:    "",
		CertNotAfter:        notAfter,
		NewCertNotAfter:     newNoAfter,
		NewCertSerialNumber: "",
	}
	_, err = test.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
		Node: node3,
	})
	require.NoError(t, err)

	for _, tt := range []struct {
		name string

		code       codes.Code
		dsError    error
		err        string
		expectLogs []spiretest.LogEntry
		expectResp *agentpb.ListAgentsResponse
		req        *agentpb.ListAgentsRequest
	}{
		{
			name: "success",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{AttestationType: true},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID), AttestationType: "t1"},
					{Id: api.ProtoFromID(node2ID), AttestationType: "t2"},
					{Id: api.ProtoFromID(node3ID), AttestationType: "t3"},
				},
			},
		},
		{
			name: "no mask",
			req:  &agentpb.ListAgentsRequest{},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{
						Id:                   api.ProtoFromID(node1ID),
						AttestationType:      "t1",
						Banned:               false,
						X509SvidExpiresAt:    notAfter,
						X509SvidSerialNumber: "badcafe",
						Selectors: []*types.Selector{
							{Type: "a", Value: "1"},
							{Type: "b", Value: "2"},
						},
					},
					{
						Id:                   api.ProtoFromID(node2ID),
						AttestationType:      "t2",
						Banned:               false,
						X509SvidExpiresAt:    notAfter,
						X509SvidSerialNumber: "deadbeef",
						Selectors: []*types.Selector{
							{Type: "a", Value: "1"},
							{Type: "c", Value: "3"},
						},
					},
					{
						Id:                   api.ProtoFromID(node3ID),
						AttestationType:      "t3",
						Banned:               true,
						X509SvidExpiresAt:    notAfter,
						X509SvidSerialNumber: "",
					},
				},
			},
		},
		{
			name: "mask all false",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
					{Id: api.ProtoFromID(node3ID)},
				},
			},
		},
		{
			name: "by attestation type",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentpb.ListAgentsRequest_Filter{
					ByAttestationType: "t1",
				},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
				},
			},
		},
		{
			name: "by banned true",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentpb.ListAgentsRequest_Filter{
					ByBanned: &wrapperspb.BoolValue{Value: true},
				},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node3ID)},
				},
			},
		},
		{
			name: "by banned false",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentpb.ListAgentsRequest_Filter{
					ByBanned: &wrapperspb.BoolValue{Value: false},
				},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
				},
			},
		},
		{
			name: "by selectors",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentpb.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Match: types.SelectorMatch_MATCH_EXACT,
						Selectors: []*types.Selector{
							{Type: "a", Value: "1"},
							{Type: "b", Value: "2"},
						},
					},
				},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
				},
			},
		},
		{
			name: "with pagination",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				PageSize:   2,
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
				},
				NextPageToken: "2",
			},
		},
		{
			name: "malformed selectors",
			req: &agentpb.ListAgentsRequest{
				Filter: &agentpb.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Selectors: []*types.Selector{{Value: "1"}},
					},
				},
			},
			code: codes.InvalidArgument,
			err:  "failed to parse selectors: missing selector type",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to parse selectors",
					Data: logrus.Fields{
						logrus.ErrorKey: "missing selector type",
					},
				},
			},
		},
		{
			name:    "ds fails",
			req:     &agentpb.ListAgentsRequest{},
			code:    codes.Internal,
			dsError: errors.New("some error"),
			err:     "failed to list agents: some error",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to list agents",
					Data: logrus.Fields{
						logrus.ErrorKey: "some error",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()
			test.ds.SetNextError(tt.dsError)

			resp, err := test.client.ListAgents(ctx, tt.req)

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			spiretest.RequireProtoEqual(t, tt.expectResp, resp)
		})
	}
}

func TestBanAgent(t *testing.T) {
	agentTrustDomain := "example.org"
	agentPath := "/spire/agent/agent-1"

	for _, tt := range []struct {
		name       string
		reqID      *types.SPIFFEID
		dsError    error
		expectCode codes.Code
		expectMsg  string
		expectLogs []spiretest.LogEntry
	}{
		{
			name: "Ban agent succeeds",
			reqID: &types.SPIFFEID{
				TrustDomain: agentTrustDomain,
				Path:        agentPath,
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Agent banned",
					Data: logrus.Fields{
						telemetry.SPIFFEID: spiffeid.Must(agentTrustDomain, agentPath).String(),
					},
				},
			},
		},
		{
			name:       "Ban agent fails if ID is nil",
			reqID:      nil,
			expectCode: codes.InvalidArgument,
			expectMsg:  "invalid agent ID: request must specify SPIFFE ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "request must specify SPIFFE ID",
					},
				},
			},
		},
		{
			name: "Ban agent fails if ID is not valid",
			reqID: &types.SPIFFEID{
				Path:        agentPath,
				TrustDomain: "ex ample.org",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  `invalid agent ID: spiffeid: unable to parse: parse "spiffe://ex ample.org/spire/agent/agent-1": invalid character " " in host name`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: `spiffeid: unable to parse: parse "spiffe://ex ample.org/spire/agent/agent-1": invalid character " " in host name`,
					},
				},
			},
		},
		{
			name: "Ban agent fails if ID is not a leaf ID",
			reqID: &types.SPIFFEID{
				TrustDomain: agentTrustDomain,
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  `invalid agent ID: "spiffe://example.org" is not an agent in trust domain "example.org"; path is empty`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: `"spiffe://example.org" is not an agent in trust domain "example.org"; path is empty`,
					},
				},
			},
		},
		{
			name: "Ban agent fails if ID is not an agent SPIFFE ID",
			reqID: &types.SPIFFEID{
				TrustDomain: agentTrustDomain,
				Path:        "agent-1",
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  `invalid agent ID: "spiffe://example.org/agent-1" is not an agent in trust domain "example.org"; path is not in the agent namespace`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: `"spiffe://example.org/agent-1" is not an agent in trust domain "example.org"; path is not in the agent namespace`,
					},
				},
			},
		},
		{
			name: "Ban agent fails if agent do not belongs to the server's own trust domain",
			reqID: &types.SPIFFEID{
				TrustDomain: "another-example.org",
				Path:        agentPath,
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  `invalid agent ID: "spiffe://another-example.org/spire/agent/agent-1" is not a member of trust domain "example.org"`,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: `"spiffe://another-example.org/spire/agent/agent-1" is not a member of trust domain "example.org"`,
					},
				},
			},
		},
		{
			name: "Ban agent fails if agent does not exists",
			reqID: &types.SPIFFEID{
				TrustDomain: agentTrustDomain,
				Path:        "/spire/agent/agent-2",
			},
			expectCode: codes.NotFound,
			expectMsg:  "agent not found",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent not found",
					Data: logrus.Fields{
						telemetry.SPIFFEID: spiffeid.Must(agentTrustDomain, "spire/agent/agent-2").String(),
					},
				},
			},
		},
		{
			name: "Ban agent fails if there is a datastore error",
			reqID: &types.SPIFFEID{
				TrustDomain: agentTrustDomain,
				Path:        agentPath,
			},
			dsError:    errors.New("unknown datastore error"),
			expectCode: codes.Internal,
			expectMsg:  "failed to ban agent: unknown datastore error",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to ban agent",
					Data: logrus.Fields{
						logrus.ErrorKey:    "unknown datastore error",
						telemetry.SPIFFEID: spiffeid.Must(agentTrustDomain, agentPath).String(),
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()
			ctx := context.Background()

			node := &common.AttestedNode{
				SpiffeId:            spiffeid.Must(agentTrustDomain, agentPath).String(),
				AttestationDataType: "attestation-type",
				CertNotAfter:        100,
				NewCertNotAfter:     200,
				CertSerialNumber:    "1234",
				NewCertSerialNumber: "1235",
			}

			_, err := test.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
				Node: node,
			})
			require.NoError(t, err)
			test.ds.SetNextError(tt.dsError)

			banResp, err := test.client.BanAgent(ctx, &agentpb.BanAgentRequest{Id: tt.reqID})
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			test.ds.SetNextError(nil)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if tt.expectCode != codes.OK {
				require.Nil(t, banResp)

				fetchResp, err := test.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
					SpiffeId: node.SpiffeId,
				})
				require.NoError(t, err)
				require.NotNil(t, fetchResp)
				require.NotZero(t, fetchResp.Node.CertSerialNumber)
				require.NotZero(t, fetchResp.Node.NewCertSerialNumber)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, banResp)

			fetchResp, err := test.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
				SpiffeId: spiffeid.Must(tt.reqID.TrustDomain, tt.reqID.Path).String(),
			})
			require.NoError(t, err)
			require.NotNil(t, fetchResp)

			node.CertSerialNumber = ""
			node.NewCertSerialNumber = ""
			spiretest.RequireProtoEqual(t, node, fetchResp.Node)
		})
	}
}

func TestDeleteAgent(t *testing.T) {
	node1 := &common.AttestedNode{
		SpiffeId: "spiffe://example.org/spire/agent/node1",
	}

	for _, tt := range []struct {
		name string

		code       codes.Code
		dsError    error
		err        string
		expectLogs []spiretest.LogEntry
		req        *agentpb.DeleteAgentRequest
	}{
		{
			name: "success",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Agent deleted",
					Data: logrus.Fields{
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/node1",
					},
				},
			},
			req: &agentpb.DeleteAgentRequest{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "/spire/agent/node1",
				},
			},
		},
		{
			name: "malformed SPIFFE ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "trust domain is empty",
					},
				},
			},
			code: codes.InvalidArgument,
			err:  "invalid agent ID: trust domain is empty",
			req: &agentpb.DeleteAgentRequest{
				Id: &types.SPIFFEID{
					TrustDomain: "",
					Path:        "spiffe://examples.org/spire/agent/node1",
				},
			},
		},
		{
			name: "not found",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent not found",
					Data: logrus.Fields{
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/notfound",
					},
				},
			},
			code: codes.NotFound,
			err:  "agent not found",
			req: &agentpb.DeleteAgentRequest{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "/spire/agent/notfound",
				},
			},
		},
		{
			name: "not an agent ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: `"spiffe://example.org/host" is not an agent in trust domain "example.org"; path is not in the agent namespace`,
					},
				},
			},
			code: codes.InvalidArgument,
			err:  `invalid agent ID: "spiffe://example.org/host" is not an agent in trust domain "example.org"; path is not in the agent namespace`,
			req: &agentpb.DeleteAgentRequest{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "host",
				},
			},
		},
		{
			name: "not member of trust domain",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: `"spiffe://another.org/spire/agent/node1" is not a member of trust domain "example.org"`,
					},
				},
			},
			code: codes.InvalidArgument,
			err:  `invalid agent ID: "spiffe://another.org/spire/agent/node1" is not a member of trust domain "example.org"`,
			req: &agentpb.DeleteAgentRequest{
				Id: &types.SPIFFEID{
					TrustDomain: "another.org",
					Path:        "/spire/agent/node1",
				},
			},
		},
		{
			name:    "ds fails",
			code:    codes.Internal,
			err:     "failed to remove agent: some error",
			dsError: errors.New("some error"),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to remove agent",
					Data: logrus.Fields{
						logrus.ErrorKey:    "some error",
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/node1",
					},
				},
			},
			req: &agentpb.DeleteAgentRequest{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "/spire/agent/node1",
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			_, err := test.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
				Node: node1,
			})
			require.NoError(t, err)
			test.ds.SetNextError(tt.dsError)

			resp, err := test.client.DeleteAgent(ctx, tt.req)

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if err != nil {
				require.Nil(t, resp)
				spiretest.RequireGRPCStatus(t, err, tt.code, tt.err)

				// Verify node was not deleted
				node, err := test.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
					SpiffeId: node1.SpiffeId,
				})
				require.NoError(t, err)
				require.NotNil(t, node.Node)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			id := spiffeid.Must(tt.req.Id.TrustDomain, tt.req.Id.Path)

			node, err := test.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
				SpiffeId: id.String(),
			})
			require.NoError(t, err)
			require.Nil(t, node.Node)
		})
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
			req:   &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-1"}},
			agent: expectedAgents[agent1],
		},
		{
			name:  "success agent-2",
			req:   &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-2"}},
			agent: expectedAgents[agent2],
		},
		{
			name: "success - with mask",
			req: &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-1"},
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
			req: &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-1"},
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
					Message: "Invalid argument: invalid agent ID",
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
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: `spiffeid: unable to parse: parse "spiffe://invalid domain": invalid character " " in host name`,
					},
				},
			},
			err:  `spiffeid: unable to parse: parse "spiffe://invalid domain": invalid character " " in host name`,
			code: codes.InvalidArgument,
		},
		{
			name: "agent does not exist",
			req:  &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/does-not-exist"}},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent not found",
					Data: logrus.Fields{
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/does-not-exist",
					},
				},
			},
			err:  "agent not found",
			code: codes.NotFound,
		},
		{
			name: "datastore error",
			req:  &agentpb.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-1"}},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch agent",
					Data: logrus.Fields{
						logrus.ErrorKey:    "datastore error",
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/agent-1",
					},
				},
			},
			err:     "failed to fetch agent: datastore error",
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

func TestRenewAgent(t *testing.T) {
	testKey := testkey.MustEC256()
	agentIDType := &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"}

	defaultNode := &common.AttestedNode{
		SpiffeId:            agentID.String(),
		AttestationDataType: "t",
		CertNotAfter:        12345,
		CertSerialNumber:    "6789",
	}

	// Create a test CSR with empty template
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, testKey)
	require.NoError(t, err)

	renewingMessage := spiretest.LogEntry{
		Level:   logrus.DebugLevel,
		Message: "Renewing agent SVID",
	}

	_, malformedError := x509.ParseCertificateRequest([]byte("malformed csr"))
	require.Error(t, malformedError)

	for _, tt := range []struct {
		name string

		dsError        []error
		createNode     *common.AttestedNode
		expectLogs     []spiretest.LogEntry
		failCallerID   bool
		failSigning    bool
		req            *agentpb.RenewAgentRequest
		expectCode     codes.Code
		expectMsg      string
		rateLimiterErr error
	}{
		{
			name:       "success",
			createNode: cloneAttestedNode(defaultNode),
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
			},
			req: &agentpb.RenewAgentRequest{
				Params: &agentpb.AgentX509SVIDParams{
					Csr: csr,
				},
			},
		},
		{
			name:       "rate limit fails",
			createNode: cloneAttestedNode(defaultNode),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Rejecting request due to renew agent rate limiting",
					Data: logrus.Fields{
						logrus.ErrorKey: "rate limit fails",
					},
				},
			},
			req:            &agentpb.RenewAgentRequest{},
			expectCode:     codes.Unknown,
			expectMsg:      "rejecting request due to renew agent rate limiting: rate limit fails",
			rateLimiterErr: errors.New("rate limit fails"),
		},
		{
			name:       "no caller ID",
			createNode: cloneAttestedNode(defaultNode),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Caller ID missing from request context",
				},
			},
			req:          &agentpb.RenewAgentRequest{},
			failCallerID: true,
			expectCode:   codes.Internal,
			expectMsg:    "caller ID missing from request context",
		},
		{
			name: "no attested node",
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent not found",
				},
			},
			req: &agentpb.RenewAgentRequest{
				Params: &agentpb.AgentX509SVIDParams{
					Csr: csr,
				},
			},
			expectCode: codes.NotFound,
			expectMsg:  "agent not found",
		},
		{
			name:       "missing CSR",
			createNode: cloneAttestedNode(defaultNode),
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: missing CSR",
				},
			},
			req: &agentpb.RenewAgentRequest{
				Params: &agentpb.AgentX509SVIDParams{},
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "missing CSR",
		},
		{
			name:       "malformed csr",
			createNode: cloneAttestedNode(defaultNode),
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to parse CSR",
					Data: logrus.Fields{
						logrus.ErrorKey: malformedError.Error()},
				},
			},
			req: &agentpb.RenewAgentRequest{
				Params: &agentpb.AgentX509SVIDParams{
					Csr: []byte("malformed CSR"),
				},
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  fmt.Sprintf("failed to parse CSR: %v", malformedError),
		},
		{
			name:       "request has nil param",
			createNode: cloneAttestedNode(defaultNode),
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: params cannot be nil",
				},
			},
			req:        &agentpb.RenewAgentRequest{},
			expectCode: codes.InvalidArgument,
			expectMsg:  "params cannot be nil",
		},
		{
			name:       "failed to sign SVID",
			createNode: cloneAttestedNode(defaultNode),
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to sign X509 SVID",
					Data: logrus.Fields{
						logrus.ErrorKey: "X509 CA is not available for signing",
					},
				},
			},
			failSigning: true,
			req: &agentpb.RenewAgentRequest{
				Params: &agentpb.AgentX509SVIDParams{
					Csr: csr,
				},
			},
			expectCode: codes.Internal,
			expectMsg:  "failed to sign X509 SVID: X509 CA is not available for signing",
		},
		{
			name:       "failed to update attested node",
			createNode: cloneAttestedNode(defaultNode),
			dsError: []error{
				errors.New("some error"),
			},
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to update agent",
					Data: logrus.Fields{
						logrus.ErrorKey: "some error",
					},
				},
			},
			req: &agentpb.RenewAgentRequest{
				Params: &agentpb.AgentX509SVIDParams{
					Csr: csr,
				},
			},
			expectCode: codes.Internal,
			expectMsg:  "failed to update agent: some error",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Setup test
			test := setupServiceTest(t)
			defer test.Cleanup()

			if tt.createNode != nil {
				_, err := test.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
					Node: tt.createNode,
				})
				require.NoError(t, err)
			}
			if tt.failSigning {
				test.ca.SetX509CA(nil)
			}

			test.rateLimiter.count = 1
			test.rateLimiter.err = tt.rateLimiterErr
			test.withCallerID = !tt.failCallerID
			for _, err := range tt.dsError {
				test.ds.AppendNextError(err)
			}
			now := test.ca.Clock().Now().UTC()
			expiredAt := now.Add(test.ca.X509SVIDTTL())

			// Send param message
			resp, err := test.client.RenewAgent(ctx, tt.req)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)

			if tt.expectCode != codes.OK {
				require.Nil(t, resp)
				spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			// Validate SVID
			spiretest.AssertProtoEqual(t, agentIDType, resp.Svid.Id)
			require.Equal(t, expiredAt.Unix(), resp.Svid.ExpiresAt)

			certChain, err := x509util.RawCertsToCertificates(resp.Svid.CertChain)
			require.NoError(t, err)
			require.NotEmpty(t, certChain)

			x509Svid := certChain[0]
			require.Equal(t, expiredAt, x509Svid.NotAfter)
			require.Equal(t, []*url.URL{agentID.URL()}, x509Svid.URIs)

			// Validate attested node in datastore
			updatedNode, err := test.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
				SpiffeId: agentID.String(),
			})
			require.NoError(t, err)
			require.NotNil(t, updatedNode)
			expectedNode := tt.createNode
			expectedNode.NewCertNotAfter = x509Svid.NotAfter.Unix()
			expectedNode.NewCertSerialNumber = x509Svid.SerialNumber.String()
			spiretest.AssertProtoEqual(t, expectedNode, updatedNode.Node)

			// No logs expected
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

func TestCreateJoinToken(t *testing.T) {
	for _, tt := range []struct {
		name          string
		request       *agentpb.CreateJoinTokenRequest
		expectLogs    []spiretest.LogEntry
		expectResults *types.JoinToken
		err           string
		code          codes.Code
		dsError       error
	}{
		{
			name: "Success Basic Create Join Token",
			request: &agentpb.CreateJoinTokenRequest{
				Ttl: 1000,
			},
		},
		{
			name: "Success Custom Value Join Token",
			request: &agentpb.CreateJoinTokenRequest{
				Ttl:   1000,
				Token: "token goes here",
			},
		},
		{
			name: "Fail Negative Ttl",
			request: &agentpb.CreateJoinTokenRequest{
				Ttl: -1000,
			},
			err:  "ttl is required, you must provide one",
			code: codes.InvalidArgument,
		},
		{
			name: "Fail Datastore Error",
			err:  "failed to create token: datatore broken",
			request: &agentpb.CreateJoinTokenRequest{
				Ttl: 1000,
			},
			dsError: errors.New("datatore broken"),
			code:    codes.Internal,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			test.ds.SetNextError(tt.dsError)

			result, err := test.client.CreateJoinToken(context.Background(), tt.request)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotEmpty(t, result.Value)
			require.NotEmpty(t, result.Value)
		})
	}
}

func TestCreateJoinTokenWithAgentId(t *testing.T) {
	test := setupServiceTest(t)

	_, err := test.client.CreateJoinToken(context.Background(), &agentpb.CreateJoinTokenRequest{
		Ttl:     1000,
		AgentId: &types.SPIFFEID{TrustDomain: "badtd.org", Path: "invalid"},
	})
	require.Error(t, err)
	spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `invalid agent ID: "spiffe://badtd.org/invalid" is not a member of trust domain "example.org"`)

	token, err := test.client.CreateJoinToken(context.Background(), &agentpb.CreateJoinTokenRequest{
		Ttl:     1000,
		AgentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "valid"},
	})
	require.NoError(t, err)
	spiretest.RequireGRPCStatusContains(t, err, codes.OK, "")

	listEntries, err := test.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)
	require.Equal(t, "spiffe://example.org/valid", listEntries.Entries[0].SpiffeId)
	require.Equal(t, "spiffe://example.org/spire/agent/join_token/"+token.Value, listEntries.Entries[0].ParentId)
	require.Equal(t, "spiffe://example.org/spire/agent/join_token/"+token.Value, listEntries.Entries[0].Selectors[0].Value)
}

func TestAttestAgent(t *testing.T) {
	testCsr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, testkey.MustEC256())
	require.NoError(t, err)

	_, expectedCsrErr := x509.ParseCertificateRequest([]byte("not a csr"))
	require.Error(t, expectedCsrErr)

	for _, tt := range []struct {
		name              string
		retry             bool
		request           *agentpb.AttestAgentRequest
		expectedID        spiffeid.ID
		expectedSelectors []*common.Selector
		expectCode        codes.Code
		expectMsg         string
		expectLogs        []spiretest.LogEntry
		rateLimiterErr    error
		dsError           []error
	}{

		{
			name:       "empty request",
			request:    &agentpb.AttestAgentRequest{},
			expectCode: codes.InvalidArgument,
			expectMsg:  "malformed param: missing params",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: malformed param",
					Data: logrus.Fields{
						logrus.ErrorKey: "missing params",
					},
				},
			},
		},

		{
			name: "empty attestation data",
			request: &agentpb.AttestAgentRequest{
				Step: &agentpb.AttestAgentRequest_Params_{
					Params: &agentpb.AttestAgentRequest_Params{},
				},
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "malformed param: missing attestation data",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: malformed param",
					Data: logrus.Fields{
						logrus.ErrorKey: "missing attestation data",
					},
				},
			},
		},

		{
			name: "missing parameters",
			request: &agentpb.AttestAgentRequest{
				Step: &agentpb.AttestAgentRequest_Params_{
					Params: &agentpb.AttestAgentRequest_Params{
						Data: &types.AttestationData{
							Type: "foo type",
						},
					},
				},
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "malformed param: missing X509-SVID parameters",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: malformed param",
					Data: logrus.Fields{
						logrus.ErrorKey: "missing X509-SVID parameters",
					},
				},
			},
		},

		{
			name: "missing attestation data type",
			request: &agentpb.AttestAgentRequest{
				Step: &agentpb.AttestAgentRequest_Params_{
					Params: &agentpb.AttestAgentRequest_Params{
						Data: &types.AttestationData{},
						Params: &agentpb.AgentX509SVIDParams{
							Csr: []byte("fake csr"),
						},
					},
				},
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "malformed param: missing attestation data type",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: malformed param",
					Data: logrus.Fields{
						logrus.ErrorKey: "missing attestation data type",
					},
				},
			},
		},

		{
			name: "missing csr",
			request: &agentpb.AttestAgentRequest{
				Step: &agentpb.AttestAgentRequest_Params_{
					Params: &agentpb.AttestAgentRequest_Params{
						Data: &types.AttestationData{
							Type: "foo type",
						},
						Params: &agentpb.AgentX509SVIDParams{},
					},
				},
			},
			expectCode: codes.InvalidArgument,
			expectMsg:  "malformed param: missing CSR",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: malformed param",
					Data: logrus.Fields{
						logrus.ErrorKey: "missing CSR",
					},
				},
			},
		},

		{
			name:           "rate limit fails",
			request:        &agentpb.AttestAgentRequest{},
			expectCode:     codes.Unknown,
			expectMsg:      "rate limit fails",
			rateLimiterErr: status.Error(codes.Unknown, "rate limit fails"),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Rejecting request due to attest agent rate limiting",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Unknown desc = rate limit fails",
					},
				},
			},
		},

		{
			name:       "join token does not exist",
			request:    getAttestAgentRequest("join_token", []byte("bad_token"), testCsr),
			expectCode: codes.InvalidArgument,
			expectMsg:  "failed to attest: join token does not exist or has already been used",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to attest: join token does not exist or has already been used",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
					},
				},
			},
		},

		{
			name:       "attest with join token",
			request:    getAttestAgentRequest("join_token", []byte("test_token"), testCsr),
			expectedID: td.NewID("/spire/agent/join_token/test_token"),
		},

		{
			name:       "attest with join token is banned",
			request:    getAttestAgentRequest("join_token", []byte("banned_token"), testCsr),
			expectCode: codes.PermissionDenied,
			expectMsg:  "failed to attest: agent is banned",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to attest: agent is banned",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
						telemetry.AgentID:          td.NewID("/spire/agent/join_token/banned_token").String(),
					},
				},
			},
		},

		{
			name:       "attest with join token is expired",
			request:    getAttestAgentRequest("join_token", []byte("expired_token"), testCsr),
			expectCode: codes.InvalidArgument,
			expectMsg:  "join token expired",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: join token expired",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
					},
				},
			},
		},

		{
			name:       "attest with join token only works once",
			retry:      true,
			request:    getAttestAgentRequest("join_token", []byte("test_token"), testCsr),
			expectCode: codes.InvalidArgument,
			expectMsg:  "failed to attest: join token does not exist or has already been used",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to attest: join token does not exist or has already been used",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
					},
				},
			},
		},

		{
			name:       "attest with result",
			request:    getAttestAgentRequest("test_type", []byte("payload_with_result"), testCsr),
			expectedID: td.NewID("/spire/agent/test_type/id_with_result"),
			expectedSelectors: []*common.Selector{
				{Type: "test_type", Value: "resolved"},
				{Type: "test_type", Value: "result"},
			},
		},

		{
			name:       "attest with result twice",
			retry:      true,
			request:    getAttestAgentRequest("test_type", []byte("payload_with_result"), testCsr),
			expectedID: td.NewID("/spire/agent/test_type/id_with_result"),
			expectedSelectors: []*common.Selector{
				{Type: "test_type", Value: "resolved"},
				{Type: "test_type", Value: "result"},
			},
		},

		{
			name:       "attest with challenge",
			request:    getAttestAgentRequest("test_type", []byte("payload_with_challenge"), testCsr),
			expectedID: td.NewID("/spire/agent/test_type/id_with_challenge"),
			expectedSelectors: []*common.Selector{
				{Type: "test_type", Value: "challenge"},
				{Type: "test_type", Value: "resolved_too"},
			},
		},

		{
			name:       "attest already attested",
			request:    getAttestAgentRequest("test_type", []byte("payload_attested_before"), testCsr),
			expectedID: td.NewID("/spire/agent/test_type/id_attested_before"),
			expectedSelectors: []*common.Selector{
				{Type: "test_type", Value: "attested_before"},
			},
		},

		{
			name:       "attest banned",
			request:    getAttestAgentRequest("test_type", []byte("payload_banned"), testCsr),
			expectCode: codes.PermissionDenied,
			expectMsg:  "failed to attest: agent is banned",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to attest: agent is banned",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "test_type",
						telemetry.AgentID:          td.NewID("/spire/agent/test_type/id_banned").String(),
					},
				},
			},
		},

		{
			name:       "attest with bad attestor",
			request:    getAttestAgentRequest("bad_type", []byte("payload_with_result"), testCsr),
			expectCode: codes.FailedPrecondition,
			expectMsg:  "could not find node attestor type",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Could not find node attestor type",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "bad_type",
					},
				},
			},
		},

		{
			name:       "attest with bad csr",
			request:    getAttestAgentRequest("test_type", []byte("payload_with_result"), []byte("not a csr")),
			expectCode: codes.InvalidArgument,
			expectMsg:  "failed to parse CSR: ",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to parse CSR",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "test_type",
						logrus.ErrorKey:            expectedCsrErr.Error(),
						telemetry.AgentID:          td.NewID("/spire/agent/test_type/id_with_result").String(),
					},
				},
			},
		},

		{
			name:       "ds: fails to fetch join token",
			request:    getAttestAgentRequest("join_token", []byte("test_token"), testCsr),
			expectCode: codes.Internal,
			expectMsg:  "failed to fetch join token",
			dsError: []error{
				errors.New("some error"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch join token",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
						logrus.ErrorKey:            "some error",
					},
				},
			},
		},

		{
			name:       "ds: fails to delete join token",
			request:    getAttestAgentRequest("join_token", []byte("test_token"), testCsr),
			expectCode: codes.Internal,
			expectMsg:  "failed to delete join token",
			dsError: []error{
				nil,
				errors.New("some error"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to delete join token",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
						logrus.ErrorKey:            "some error",
					},
				},
			},
		},

		{
			name:       "ds: fails to fetch agent",
			request:    getAttestAgentRequest("join_token", []byte("test_token"), testCsr),
			expectCode: codes.Internal,
			expectMsg:  "failed to fetch agent",
			dsError: []error{
				nil,
				nil,
				errors.New("some error"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch agent",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
						logrus.ErrorKey:            "some error",
						telemetry.AgentID:          td.NewID("/spire/agent/join_token/test_token").String(),
					},
				},
			},
		},

		{
			name:       "ds: fails to update selectors",
			request:    getAttestAgentRequest("join_token", []byte("test_token"), testCsr),
			expectCode: codes.Internal,
			expectMsg:  "failed to update selectors",
			dsError: []error{
				nil,
				nil,
				nil,
				errors.New("some error"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Could not find node resolver",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
						telemetry.AgentID:          td.NewID("/spire/agent/join_token/test_token").String(),
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to update selectors",

					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
						logrus.ErrorKey:            "some error",
						telemetry.AgentID:          td.NewID("/spire/agent/join_token/test_token").String(),
					},
				},
			},
		},

		{
			name:       "ds: fails to create attested agent",
			request:    getAttestAgentRequest("join_token", []byte("test_token"), testCsr),
			expectCode: codes.Internal,
			expectMsg:  "failed to create attested agent",
			dsError: []error{
				nil,
				nil,
				nil,
				nil,
				errors.New("some error"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Could not find node resolver",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
						telemetry.AgentID:          td.NewID("/spire/agent/join_token/test_token").String(),
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to create attested agent",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
						logrus.ErrorKey:            "some error",
						telemetry.AgentID:          td.NewID("/spire/agent/join_token/test_token").String(),
					},
				},
			},
		},

		{
			name:       "ds: fails to update attested agent",
			request:    getAttestAgentRequest("test_type", []byte("payload_attested_before"), testCsr),
			expectCode: codes.Internal,
			expectMsg:  "failed to update attested agent",
			dsError: []error{
				nil,
				nil,
				errors.New("some error"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to update attested agent",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "test_type",
						logrus.ErrorKey:            "some error",
						telemetry.AgentID:          td.NewID("/spire/agent/test_type/id_attested_before").String(),
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			test := setupServiceTest(t)
			defer test.Cleanup()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			test.setupAttestor(t)
			test.setupResolver(t)
			test.setupJoinTokens(ctx, t)
			test.setupNodes(ctx, t)

			test.rateLimiter.count = 1
			test.rateLimiter.err = tt.rateLimiterErr
			for _, err := range tt.dsError {
				test.ds.AppendNextError(err)
			}

			// exercise
			stream, err := test.client.AttestAgent(ctx)
			require.NoError(t, err)
			result, err := attest(t, stream, tt.request)
			errClose := stream.CloseSend()
			require.NoError(t, errClose)

			if tt.retry {
				// make sure that the first request went well
				require.NoError(t, err)
				require.NotNil(t, result)
				// clear entries from the previous run
				test.logHook.Reset()

				// attest once more
				stream, err = test.client.AttestAgent(ctx)
				require.NoError(t, err)
				result, err = attest(t, stream, tt.request)
				errClose := stream.CloseSend()
				require.NoError(t, errClose)
			}

			spiretest.RequireGRPCStatusContains(t, err, tt.expectCode, tt.expectMsg)
			switch {
			case tt.expectCode != codes.OK:
				require.Nil(t, result)
				spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			default:
				require.NotNil(t, result)
				test.assertAttestAgentResult(t, tt.expectedID, result)
				test.assertAgentWasStored(t, tt.expectedID.String(), tt.expectedSelectors)
			}
		})
	}
}

type serviceTest struct {
	client       agentpb.AgentClient
	done         func()
	ds           *fakedatastore.DataStore
	ca           *fakeserverca.CA
	cat          *fakeservercatalog.Catalog
	logHook      *test.Hook
	rateLimiter  *fakeRateLimiter
	withCallerID bool
	pluginCloser func()
}

func (s *serviceTest) Cleanup() {
	s.done()
	if s.pluginCloser != nil {
		s.pluginCloser()
	}
}

func setupServiceTest(t *testing.T) *serviceTest {
	ca := fakeserverca.New(t, td, &fakeserverca.Options{})
	ds := fakedatastore.New(t)
	cat := fakeservercatalog.New()

	service := agent.New(agent.Config{
		ServerCA:    ca,
		DataStore:   ds,
		TrustDomain: td,
		Clock:       clock.NewMock(t),
		Catalog:     cat,
	})

	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel
	registerFn := func(s *grpc.Server) {
		agent.RegisterService(s, service)
	}

	rateLimiter := &fakeRateLimiter{}

	test := &serviceTest{
		ca:          ca,
		ds:          ds,
		cat:         cat,
		logHook:     logHook,
		rateLimiter: rateLimiter,
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		ctx = rpccontext.WithRateLimiter(ctx, rateLimiter)
		if test.withCallerID {
			ctx = rpccontext.WithCallerID(ctx, agentID)
		}
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)
	test.done = done
	test.client = agentpb.NewAgentClient(conn)

	return test
}

func (s *serviceTest) setupAttestor(t *testing.T) {
	attestorConfig := fakeservernodeattestor.Config{
		Data: map[string]string{
			"payload_attested_before": "id_attested_before",
			"payload_with_challenge":  "id_with_challenge",
			"payload_with_result":     "id_with_result",
			"payload_banned":          "id_banned",
		},
		Selectors: map[string][]string{
			"id_with_result":     {"result"},
			"id_attested_before": {"attested_before"},
			"id_with_challenge":  {"challenge"},
			"id_banned":          {"banned"},
		},
	}

	attestorConfig.Challenges = map[string][]string{"id_with_challenge": {"challenge_response"}}

	fakeServerAttestor := fakeservernodeattestor.New("test_type", attestorConfig)
	fakeServerPlugin := nodeattestor.PluginServer(fakeServerAttestor)
	fakeCatalogPlugin := catalog.MakePlugin("test_type", fakeServerPlugin)

	loadedPlugin, err := catalog.LoadBuiltInPlugin(context.Background(), catalog.BuiltInPlugin{
		Log:          nil,
		Plugin:       fakeCatalogPlugin,
		HostServices: nil,
	})
	require.NoError(t, err, "unable to load plugin")

	var fakeNodeAttestorClient nodeattestor.NodeAttestor
	if err := loadedPlugin.Fill(&fakeNodeAttestorClient); err != nil {
		loadedPlugin.Close()
		require.NoError(t, err, "unable to satisfy plugin client")
	}

	s.pluginCloser = loadedPlugin.Close
	s.cat.AddNodeAttestorNamed("test_type", fakeNodeAttestorClient)
}

func (s *serviceTest) setupResolver(t *testing.T) {
	resolverConfig := fakenoderesolver.Config{
		Selectors: map[string][]string{
			td.NewID("/spire/agent/test_type/id_with_result").String():    {"resolved"},
			td.NewID("/spire/agent/test_type/id_with_challenge").String(): {"resolved_too"},
		},
	}

	fakeServerAttestor := fakenoderesolver.New("test_type", resolverConfig)
	fakeServerPlugin := noderesolver.PluginServer(fakeServerAttestor)
	fakeCatalogPlugin := catalog.MakePlugin("test_type", fakeServerPlugin)

	loadedPlugin, err := catalog.LoadBuiltInPlugin(context.Background(), catalog.BuiltInPlugin{
		Log:          nil,
		Plugin:       fakeCatalogPlugin,
		HostServices: nil,
	})
	require.NoError(t, err, "unable to load plugin")

	var fakeNodeResolverClient noderesolver.NodeResolver
	if err := loadedPlugin.Fill(&fakeNodeResolverClient); err != nil {
		loadedPlugin.Close()
		require.NoError(t, err, "unable to satisfy plugin client")
	}

	s.pluginCloser = loadedPlugin.Close
	s.cat.AddNodeResolverNamed("test_type", fakeNodeResolverClient)
}

func (s *serviceTest) setupNodes(ctx context.Context, t *testing.T) {
	req := &datastore.CreateAttestedNodeRequest{
		Node: &common.AttestedNode{
			AttestationDataType: "test_type",
			SpiffeId:            td.NewID("/spire/agent/test_type/id_attested_before").String(),
			CertSerialNumber:    "test_serial_number",
		}}
	_, err := s.ds.CreateAttestedNode(ctx, req)
	require.NoError(t, err)

	req = &datastore.CreateAttestedNodeRequest{
		Node: &common.AttestedNode{
			AttestationDataType: "test_type",
			SpiffeId:            td.NewID("/spire/agent/test_type/id_banned").String(),
			CertNotAfter:        0,
			CertSerialNumber:    "",
		}}
	_, err = s.ds.CreateAttestedNode(ctx, req)
	require.NoError(t, err)

	req = &datastore.CreateAttestedNodeRequest{
		Node: &common.AttestedNode{
			AttestationDataType: "join_token",
			SpiffeId:            td.NewID("/spire/agent/join_token/banned_token").String(),
			CertNotAfter:        0,
			CertSerialNumber:    "",
		}}
	_, err = s.ds.CreateAttestedNode(ctx, req)
	require.NoError(t, err)
}

func (s *serviceTest) setupJoinTokens(ctx context.Context, t *testing.T) {
	_, err := s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: &datastore.JoinToken{
			Token:  "test_token",
			Expiry: time.Now().Unix() + int64(60*10),
		},
	})
	require.NoError(t, err)

	_, err = s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: &datastore.JoinToken{
			Token:  "banned_token",
			Expiry: time.Now().Unix() + int64(60*10),
		},
	})
	require.NoError(t, err)

	_, err = s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: &datastore.JoinToken{
			Token:  "expired_token",
			Expiry: time.Now().Unix() - int64(60*10),
		},
	})
	require.NoError(t, err)
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

func (s *serviceTest) assertAttestAgentResult(t *testing.T, expectedID spiffeid.ID, result *agentpb.AttestAgentResponse_Result) {
	now := s.ca.Clock().Now().UTC()
	expiredAt := now.Add(s.ca.X509SVIDTTL())

	require.NotNil(t, result.Svid)
	expectedIDType := &types.SPIFFEID{TrustDomain: expectedID.TrustDomain().String(), Path: expectedID.Path()}
	spiretest.AssertProtoEqual(t, expectedIDType, result.Svid.Id)
	assert.Equal(t, expiredAt.Unix(), result.Svid.ExpiresAt)

	certChain, err := x509util.RawCertsToCertificates(result.Svid.CertChain)
	require.NoError(t, err)
	require.NotEmpty(t, certChain)

	x509Svid := certChain[0]
	assert.Equal(t, expiredAt, x509Svid.NotAfter)
	require.Equal(t, []*url.URL{expectedID.URL()}, x509Svid.URIs)
}

func (s *serviceTest) assertAgentWasStored(t *testing.T, expectedID string, expectedSelectors []*common.Selector) {
	attestedAgent, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
		SpiffeId: expectedID,
	})
	require.NoError(t, err)
	require.NotNil(t, attestedAgent.Node)
	require.Equal(t, expectedID, attestedAgent.Node.SpiffeId)

	agentSelectors, err := s.ds.GetNodeSelectors(ctx, &datastore.GetNodeSelectorsRequest{
		SpiffeId: expectedID,
	})
	require.NoError(t, err)
	require.NotNil(t, agentSelectors.Selectors)
	require.EqualValues(t, expectedSelectors, agentSelectors.Selectors.Selectors)
}

type fakeRateLimiter struct {
	count int
	err   error
}

func (f *fakeRateLimiter) RateLimit(ctx context.Context, count int) error {
	if f.count != count {
		return fmt.Errorf("rate limiter got %d but expected %d", count, f.count)
	}

	return f.err
}

func cloneAttestedNode(aNode *common.AttestedNode) *common.AttestedNode {
	return proto.Clone(aNode).(*common.AttestedNode)
}

func getAttestAgentRequest(attType string, payload []byte, csr []byte) *agentpb.AttestAgentRequest {
	return &agentpb.AttestAgentRequest{
		Step: &agentpb.AttestAgentRequest_Params_{
			Params: &agentpb.AttestAgentRequest_Params{
				Data: &types.AttestationData{
					Type:    attType,
					Payload: payload,
				},
				Params: &agentpb.AgentX509SVIDParams{
					Csr: csr,
				},
			},
		},
	}
}

func attest(t *testing.T, stream agentpb.Agent_AttestAgentClient, request *agentpb.AttestAgentRequest) (*agentpb.AttestAgentResponse_Result, error) {
	var result *agentpb.AttestAgentResponse_Result

	for {
		// send
		err := stream.Send(request)
		require.NoError(t, err)

		// recv
		resp, err := stream.Recv()
		challenge := resp.GetChallenge()
		result = resp.GetResult()

		if challenge != nil {
			// build new request to be sent
			request = &agentpb.AttestAgentRequest{
				Step: &agentpb.AttestAgentRequest_ChallengeResponse{
					ChallengeResponse: challenge,
				}}

			continue
		}
		return result, err
	}
}
