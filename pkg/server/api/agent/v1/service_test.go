package agent_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/agent/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	agentpb "github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
					ByBanned: &wrappers.BoolValue{Value: true},
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
					ByBanned: &wrappers.BoolValue{Value: false},
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
					Message: "Failed to parse selectors",
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
		name            string
		reqID           *types.SPIFFEID
		dsError         error
		expectedErr     error
		expectedLogMsgs []spiretest.LogEntry
	}{
		{
			name: "Ban agent succeeds",
			reqID: &types.SPIFFEID{
				TrustDomain: agentTrustDomain,
				Path:        agentPath,
			},
			expectedLogMsgs: []spiretest.LogEntry{
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
			name:        "Ban agent fails if ID is nil",
			reqID:       nil,
			expectedErr: status.Error(codes.InvalidArgument, "invalid SPIFFE ID: request must specify SPIFFE ID"),
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: invalid SPIFFE ID",
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
			expectedErr: status.Error(codes.InvalidArgument, "invalid SPIFFE ID: spiffeid: unable to parse: parse spiffe://ex ample.org: invalid character \" \" in host name"),
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: invalid SPIFFE ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "spiffeid: unable to parse: parse spiffe://ex ample.org: invalid character \" \" in host name",
					},
				},
			},
		},
		{
			name: "Ban agent fails if ID is not a leaf ID",
			reqID: &types.SPIFFEID{
				TrustDomain: agentTrustDomain,
			},
			expectedErr: status.Error(codes.InvalidArgument, "not an agent ID"),
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: not an agent ID",
					Data: logrus.Fields{
						telemetry.SPIFFEID: spiffeid.RequireTrustDomainFromString(agentTrustDomain).IDString(),
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
			expectedErr: status.Error(codes.InvalidArgument, "not an agent ID"),
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: not an agent ID",
					Data: logrus.Fields{
						telemetry.SPIFFEID: spiffeid.Must(agentTrustDomain, "agent-1").String(),
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
			expectedErr: status.Error(codes.InvalidArgument, "cannot ban an agent that does not belong to this trust domain"),
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: cannot ban an agent that does not belong to this trust domain",
					Data: logrus.Fields{
						telemetry.SPIFFEID: spiffeid.Must("another-example.org", agentPath).String(),
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
			expectedErr: status.Error(codes.NotFound, "agent not found: rpc error: code = NotFound desc = datastore-sql: record not found"),
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent not found",
					Data: logrus.Fields{
						logrus.ErrorKey:    "rpc error: code = NotFound desc = datastore-sql: record not found",
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
			dsError:     errors.New("unknown datastore error"),
			expectedErr: status.Error(codes.Internal, "unable to ban agent: unknown datastore error"),
			expectedLogMsgs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Unable to ban agent",
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
			test.ds.SetNextError(nil)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectedLogMsgs)
			if tt.expectedErr != nil {
				require.Equal(t, tt.expectedErr, err)
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
					Message: "Invalid request: invalid SPIFFE ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "spiffeid: trust domain is empty",
					},
				},
			},
			code: codes.InvalidArgument,
			err:  "invalid SPIFFE ID: spiffeid: trust domain is empty",
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
						logrus.ErrorKey:    "rpc error: code = NotFound desc = datastore-sql: record not found",
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
			name: "no agent ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: not an agent ID",
					Data: logrus.Fields{
						telemetry.SPIFFEID: "spiffe://example.org/host",
					},
				},
			},
			code: codes.InvalidArgument,
			err:  "not an agent ID",
			req: &agentpb.DeleteAgentRequest{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "host",
				},
			},
		},
		{
			name: "no member of trust domain",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: cannot ban an agent that does not belong to this trust domain",
					Data: logrus.Fields{
						telemetry.SPIFFEID: "spiffe://another.org/spire/agent/node1",
					},
				},
			},
			code: codes.InvalidArgument,
			err:  "cannot ban an agent that does not belong to this trust domain",
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

			id, err := api.IDFromProto(tt.req.Id)
			require.NoError(t, err)

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
					Message: "Failed to parse agent ID",
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
					Message: "Failed to parse agent ID",
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
					Message: "Failed to fetch node",
					Data: logrus.Fields{
						logrus.ErrorKey:    "datastore error",
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/agent-1",
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
		ackError       error
		ackReq         *agentpb.RenewAgentRequest
		createNode     *common.AttestedNode
		expectLogs     []spiretest.LogEntry
		failCallerID   bool
		failSigning    bool
		paramsError    error
		paramReq       *agentpb.RenewAgentRequest
		rateLimiterErr error
	}{
		{
			name:       "success",
			createNode: cloneAttestedNode(defaultNode),
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
			},
			paramReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Params{
					Params: &agentpb.AgentX509SVIDParams{
						Csr: csr,
					},
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
						logrus.ErrorKey: "rpc error: code = Unknown desc = rate limit fails",
					},
				},
			},
			paramsError: status.Error(codes.Unknown, "rate limit fails"),
			paramReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Params{
					Params: &agentpb.AgentX509SVIDParams{
						Csr: csr,
					},
				},
			},
			rateLimiterErr: status.Error(codes.Unknown, "rate limit fails"),
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
			failCallerID: true,
			paramsError:  status.Error(codes.Internal, "caller ID missing from request context"),
			paramReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Params{
					Params: &agentpb.AgentX509SVIDParams{
						Csr: csr,
					},
				},
			},
		},
		{
			name:       "invalid param type",
			createNode: cloneAttestedNode(defaultNode),
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: expected params step but got *agent.RenewAgentRequest_Params",
				},
			},
			paramReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Ack_{Ack: &agentpb.RenewAgentRequest_Ack{}},
			},
			paramsError: status.Error(codes.InvalidArgument, "expected params step but got *agent.RenewAgentRequest_Params"),
		},
		{
			name: "no attested node",
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent not found",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = NotFound desc = datastore-sql: record not found",
					},
				},
			},
			paramReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Params{
					Params: &agentpb.AgentX509SVIDParams{
						Csr: csr,
					},
				},
			},
			paramsError: status.Error(codes.NotFound, "agent not found: rpc error: code = NotFound desc = datastore-sql: record not found"),
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
			paramReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Params{
					Params: &agentpb.AgentX509SVIDParams{},
				},
			},
			paramsError: status.Error(codes.InvalidArgument, "missing CSR"),
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
			paramReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Params{
					Params: &agentpb.AgentX509SVIDParams{
						Csr: []byte("malformed CSR"),
					},
				},
			},
			paramsError: status.Errorf(codes.InvalidArgument, "failed to parse CSR: %v", malformedError),
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
			paramReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Params{
					Params: &agentpb.AgentX509SVIDParams{
						Csr: csr,
					},
				},
			},
			paramsError: status.Error(codes.Internal, "failed to sign X509 SVID: X509 CA is not available for signing"),
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
			paramReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Params{
					Params: &agentpb.AgentX509SVIDParams{
						Csr: csr,
					},
				},
			},
			paramsError: status.Error(codes.Internal, "failed to update agent: some error"),
		},
		{
			name:       "ack invalid type",
			createNode: cloneAttestedNode(defaultNode),
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: expected ack step but got *agent.RenewAgentRequest_Ack_",
				},
			},
			paramReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Params{
					Params: &agentpb.AgentX509SVIDParams{
						Csr: csr,
					},
				},
			},
			ackReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Params{
					Params: &agentpb.AgentX509SVIDParams{},
				},
			},
			ackError: status.Error(codes.InvalidArgument, "expected ack step but got *agent.RenewAgentRequest_Ack_"),
		},
		{
			name:       "failed to update attested node after ack",
			createNode: cloneAttestedNode(defaultNode),
			dsError: []error{
				nil,
				nil,
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
			paramReq: &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Params{
					Params: &agentpb.AgentX509SVIDParams{
						Csr: csr,
					},
				},
			},
			ackError: status.Error(codes.Internal, "failed to update agent: some error"),
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
			stream, err := test.client.RenewAgent(ctx)
			require.NoError(t, err)

			err = stream.Send(tt.paramReq)
			require.NoError(t, err)

			// Get SVID as response
			resp, err := stream.Recv()
			if tt.paramsError != nil {
				require.Nil(t, resp)
				require.Equal(t, tt.paramsError, err)
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

			// Send ack message
			ackReq := &agentpb.RenewAgentRequest{
				Step: &agentpb.RenewAgentRequest_Ack_{Ack: &agentpb.RenewAgentRequest_Ack{}},
			}
			if tt.ackReq != nil {
				ackReq = tt.ackReq
			}

			err = stream.Send(ackReq)
			require.NoError(t, err)

			// EOF is expected
			_, err = stream.Recv()
			if tt.ackError != nil {
				require.Equal(t, tt.ackError, err)
				spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
				return
			}
			require.Equal(t, io.EOF, err)

			// Verify attested node certificate data is updated
			updatedNode, err = test.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
				SpiffeId: agentID.String(),
			})
			require.NoError(t, err)
			require.NotNil(t, updatedNode)

			expectedNode.CertNotAfter = x509Svid.NotAfter.Unix()
			expectedNode.CertSerialNumber = x509Svid.SerialNumber.String()
			expectedNode.NewCertNotAfter = 0
			expectedNode.NewCertSerialNumber = ""
			spiretest.AssertProtoEqual(t, expectedNode, updatedNode.Node)
			// No logs expected
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

type serviceTest struct {
	ca           *fakeserverca.CA
	client       agentpb.AgentClient
	done         func()
	ds           *fakedatastore.DataStore
	logHook      *test.Hook
	rateLimiter  *fakeRateLimiter
	withCallerID bool
}

func (s *serviceTest) Cleanup() {
	s.done()
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
	spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "requested agent SPIFFE ID does not match server trust domain")

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

func setupServiceTest(t *testing.T) *serviceTest {
	ca := fakeserverca.New(t, td.String(), &fakeserverca.Options{})
	ds := fakedatastore.New(t)
	service := agent.New(agent.Config{
		ServerCA:    ca,
		DataStore:   ds,
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
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
