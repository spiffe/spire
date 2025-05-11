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

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	agent "github.com/spiffe/spire/pkg/server/api/agent/v1"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeservernodeattestor"
	"github.com/spiffe/spire/test/grpctest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	agent1 = "spiffe://example.org/spire/agent/agent-1"
	agent2 = "spiffe://example.org/spire/agent/agent-2"
)

var (
	ctx     = context.Background()
	td      = spiffeid.RequireTrustDomainFromString("example.org")
	agentID = spiffeid.RequireFromPath(td, "/agent")
	testKey = testkey.MustEC256()

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

	testNodeSelectors = map[string][]*common.Selector{
		agent1: {
			{
				Type:  "node-selector-type-1",
				Value: "node-selector-value-1",
			},
		},
		agent2: {
			{
				Type:  "node-selector-type-2",
				Value: "node-selector-value-2",
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
					Type:  testNodeSelectors[agent1][0].Type,
					Value: testNodeSelectors[agent1][0].Value,
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
					Type:  testNodeSelectors[agent2][0].Type,
					Value: testNodeSelectors[agent2][0].Value,
				},
			},
			Banned: true,
		},
	}
)

func TestCountAgents(t *testing.T) {
	ids := []spiffeid.ID{
		spiffeid.RequireFromPath(td, "/node1"),
		spiffeid.RequireFromPath(td, "/node2"),
		spiffeid.RequireFromPath(td, "/node3"),
	}

	for _, tt := range []struct {
		name       string
		count      int32
		resp       *agentv1.CountAgentsResponse
		code       codes.Code
		dsError    error
		err        string
		expectLogs []spiretest.LogEntry
	}{
		{
			name:  "0 nodes",
			count: 0,
			resp:  &agentv1.CountAgentsResponse{Count: 0},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name:  "1 node",
			count: 1,
			resp:  &agentv1.CountAgentsResponse{Count: 1},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name:  "2 nodes",
			count: 2,
			resp:  &agentv1.CountAgentsResponse{Count: 2},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name:  "3 nodes",
			count: 3,
			resp:  &agentv1.CountAgentsResponse{Count: 3},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to count agents: some error",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, 0)
			defer test.Cleanup()

			for i := range int(tt.count) {
				now := time.Now()
				_, err := test.ds.CreateAttestedNode(ctx, &common.AttestedNode{
					SpiffeId:            ids[i].String(),
					AttestationDataType: "t1",
					CertSerialNumber:    "badcafe",
					CertNotAfter:        now.Add(-time.Minute).Unix(),
					NewCertNotAfter:     now.Add(time.Minute).Unix(),
					NewCertSerialNumber: "new badcafe",
					Selectors: []*common.Selector{
						{Type: "a", Value: "1"},
						{Type: "b", Value: "2"},
					},
				})
				require.NoError(t, err)
			}

			test.ds.SetNextError(tt.dsError)
			resp, err := test.client.CountAgents(ctx, &agentv1.CountAgentsRequest{})

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
	test := setupServiceTest(t, 0)
	defer test.Cleanup()

	notAfter := time.Now().Add(-time.Minute).Unix()
	newNoAfter := time.Now().Add(time.Minute).Unix()
	node1ID := spiffeid.RequireFromPath(td, "/node1")
	node1 := &common.AttestedNode{
		SpiffeId:            node1ID.String(),
		AttestationDataType: "t1",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        notAfter,
		NewCertNotAfter:     newNoAfter,
		NewCertSerialNumber: "new badcafe",
		CanReattest:         false,
		Selectors: []*common.Selector{
			{Type: "a", Value: "1"},
			{Type: "b", Value: "2"},
		},
	}
	_, err := test.ds.CreateAttestedNode(ctx, node1)
	require.NoError(t, err)
	err = test.ds.SetNodeSelectors(ctx, node1.SpiffeId, node1.Selectors)
	require.NoError(t, err)

	node2ID := spiffeid.RequireFromPath(td, "/node2")
	node2 := &common.AttestedNode{
		SpiffeId:            node2ID.String(),
		AttestationDataType: "t2",
		CertSerialNumber:    "deadbeef",
		CertNotAfter:        notAfter,
		NewCertNotAfter:     newNoAfter,
		NewCertSerialNumber: "new deadbeef",
		CanReattest:         false,
		Selectors: []*common.Selector{
			{Type: "a", Value: "1"},
			{Type: "c", Value: "3"},
		},
	}
	_, err = test.ds.CreateAttestedNode(ctx, node2)
	require.NoError(t, err)
	err = test.ds.SetNodeSelectors(ctx, node2.SpiffeId, node2.Selectors)
	require.NoError(t, err)

	node3ID := spiffeid.RequireFromPath(td, "/node3")
	node3 := &common.AttestedNode{
		SpiffeId:            node3ID.String(),
		AttestationDataType: "t3",
		CertSerialNumber:    "",
		CertNotAfter:        notAfter,
		NewCertNotAfter:     newNoAfter,
		NewCertSerialNumber: "",
		CanReattest:         true,
	}
	_, err = test.ds.CreateAttestedNode(ctx, node3)
	require.NoError(t, err)

	for _, tt := range []struct {
		name string

		code       codes.Code
		dsError    error
		err        string
		expectLogs []spiretest.LogEntry
		expectResp *agentv1.ListAgentsResponse
		req        *agentv1.ListAgentsRequest
	}{
		{
			name: "success",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{AttestationType: true},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID), AttestationType: "t1"},
					{Id: api.ProtoFromID(node2ID), AttestationType: "t2"},
					{Id: api.ProtoFromID(node3ID), AttestationType: "t3"},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name: "no mask",
			req:  &agentv1.ListAgentsRequest{},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{
						Id:                   api.ProtoFromID(node1ID),
						AttestationType:      "t1",
						Banned:               false,
						CanReattest:          false,
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
						CanReattest:          false,
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
						CanReattest:          true,
						X509SvidExpiresAt:    notAfter,
						X509SvidSerialNumber: "",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name: "mask all false",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
					{Id: api.ProtoFromID(node3ID)},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name: "by attestation type",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					ByAttestationType: "t1",
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.NodeAttestorType: "t1",
					},
				},
			},
		},
		{
			name: "by banned true",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					ByBanned: &wrapperspb.BoolValue{Value: true},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node3ID)},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.ByBanned: "true",
					},
				},
			},
		},
		{
			name: "by banned false",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					ByBanned: &wrapperspb.BoolValue{Value: false},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.ByBanned: "false",
					},
				},
			},
		},
		{
			name: "by can re-attest true",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					ByCanReattest: &wrapperspb.BoolValue{Value: true},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node3ID)},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "success",
						telemetry.Type:          "audit",
						telemetry.ByCanReattest: "true",
					},
				},
			},
		},
		{
			name: "by can re-attest false",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					ByCanReattest: &wrapperspb.BoolValue{Value: false},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "success",
						telemetry.Type:          "audit",
						telemetry.ByCanReattest: "false",
					},
				},
			},
		},
		{
			name: "by selectors",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Match: types.SelectorMatch_MATCH_EXACT,
						Selectors: []*types.Selector{
							{Type: "a", Value: "1"},
							{Type: "b", Value: "2"},
						},
					},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:          "success",
						telemetry.Type:            "audit",
						telemetry.BySelectorMatch: "MATCH_EXACT",
						telemetry.BySelectors:     "a:1,b:2",
					},
				},
			},
		},
		{
			name: "by selectors - match any",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Match: types.SelectorMatch_MATCH_ANY,
						Selectors: []*types.Selector{
							{Type: "a", Value: "1"},
							{Type: "b", Value: "2"},
						},
					},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:          "success",
						telemetry.Type:            "audit",
						telemetry.BySelectorMatch: "MATCH_ANY",
						telemetry.BySelectors:     "a:1,b:2",
					},
				},
			},
		},
		{
			name: "by selectors - match any (no results)",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Match: types.SelectorMatch_MATCH_ANY,
						Selectors: []*types.Selector{
							{Type: "d", Value: "2"},
						},
					},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:          "success",
						telemetry.Type:            "audit",
						telemetry.BySelectorMatch: "MATCH_ANY",
						telemetry.BySelectors:     "d:2",
					},
				},
			},
		},
		{
			name: "by selectors - match exact",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Match: types.SelectorMatch_MATCH_EXACT,
						Selectors: []*types.Selector{
							{Type: "a", Value: "1"},
							{Type: "b", Value: "2"},
						},
					},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:          "success",
						telemetry.Type:            "audit",
						telemetry.BySelectorMatch: "MATCH_EXACT",
						telemetry.BySelectors:     "a:1,b:2",
					},
				},
			},
		},
		{
			name: "by selectors - match exact (no results)",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Match: types.SelectorMatch_MATCH_EXACT,
						Selectors: []*types.Selector{
							{Type: "b", Value: "2"},
							{Type: "c", Value: "3"},
						},
					},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:          "success",
						telemetry.Type:            "audit",
						telemetry.BySelectorMatch: "MATCH_EXACT",
						telemetry.BySelectors:     "b:2,c:3",
					},
				},
			},
		},
		{
			name: "by selectors - match subset",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Match: types.SelectorMatch_MATCH_SUBSET,
						Selectors: []*types.Selector{
							{Type: "a", Value: "1"},
							{Type: "c", Value: "3"},
						},
					},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node2ID)},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:          "success",
						telemetry.Type:            "audit",
						telemetry.BySelectorMatch: "MATCH_SUBSET",
						telemetry.BySelectors:     "a:1,c:3",
					},
				},
			},
		},
		{
			name: "by selectors - match subset (no results)",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Match: types.SelectorMatch_MATCH_SUBSET,
						Selectors: []*types.Selector{
							{Type: "b", Value: "2"},
							{Type: "c", Value: "3"},
						},
					},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:          "success",
						telemetry.Type:            "audit",
						telemetry.BySelectorMatch: "MATCH_SUBSET",
						telemetry.BySelectors:     "b:2,c:3",
					},
				},
			},
		},
		{
			name: "by selectors - match superset",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Match: types.SelectorMatch_MATCH_SUPERSET,
						Selectors: []*types.Selector{
							{Type: "a", Value: "1"},
						},
					},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:          "success",
						telemetry.Type:            "audit",
						telemetry.BySelectorMatch: "MATCH_SUPERSET",
						telemetry.BySelectors:     "a:1",
					},
				},
			},
		},
		{
			name: "by selectors - match superset (no results)",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentv1.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Match: types.SelectorMatch_MATCH_SUPERSET,
						Selectors: []*types.Selector{
							{Type: "b", Value: "2"},
							{Type: "c", Value: "3"},
						},
					},
				},
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:          "success",
						telemetry.Type:            "audit",
						telemetry.BySelectorMatch: "MATCH_SUPERSET",
						telemetry.BySelectors:     "b:2,c:3",
					},
				},
			},
		},
		{
			name: "with pagination",
			req: &agentv1.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				PageSize:   2,
			},
			expectResp: &agentv1.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
				},
				NextPageToken: "2",
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
					},
				},
			},
		},
		{
			name: "malformed selectors",
			req: &agentv1.ListAgentsRequest{
				Filter: &agentv1.ListAgentsRequest_Filter{
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:          "error",
						telemetry.Type:            "audit",
						telemetry.StatusCode:      "InvalidArgument",
						telemetry.StatusMessage:   "failed to parse selectors: missing selector type",
						telemetry.BySelectorMatch: "MATCH_EXACT",
						telemetry.BySelectors:     ":1",
					},
				},
			},
		},
		{
			name:    "ds fails",
			req:     &agentv1.ListAgentsRequest{},
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to list agents: some error",
					},
				},
			},
		},
	} {
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
				TrustDomain: td.Name(),
				Path:        agentPath,
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Agent banned",
					Data: logrus.Fields{
						telemetry.SPIFFEID: spiffeid.RequireFromPath(td, agentPath).String(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/agent-1",
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid agent ID: request must specify SPIFFE ID",
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
			expectMsg:  "invalid agent ID: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid agent ID: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
					},
				},
			},
		},
		{
			name: "Ban agent fails if ID is not a leaf ID",
			reqID: &types.SPIFFEID{
				TrustDomain: td.Name(),
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: `invalid agent ID: "spiffe://example.org" is not an agent in trust domain "example.org"; path is empty`,
					},
				},
			},
		},
		{
			name: "Ban agent fails if ID is not an agent SPIFFE ID",
			reqID: &types.SPIFFEID{
				TrustDomain: td.Name(),
				Path:        "/agent-1",
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: `invalid agent ID: "spiffe://example.org/agent-1" is not an agent in trust domain "example.org"; path is not in the agent namespace`,
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: `invalid agent ID: "spiffe://another-example.org/spire/agent/agent-1" is not a member of trust domain "example.org"`,
					},
				},
			},
		},
		{
			name: "Ban agent fails if agent does not exists",
			reqID: &types.SPIFFEID{
				TrustDomain: td.Name(),
				Path:        "/spire/agent/agent-2",
			},
			expectCode: codes.NotFound,
			expectMsg:  "agent not found",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent not found",
					Data: logrus.Fields{
						telemetry.SPIFFEID: spiffeid.RequireFromPath(td, "/spire/agent/agent-2").String(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.SPIFFEID:      "spiffe://example.org/spire/agent/agent-2",
						telemetry.StatusCode:    "NotFound",
						telemetry.StatusMessage: "agent not found",
					},
				},
			},
		},
		{
			name: "Ban agent fails if there is a datastore error",
			reqID: &types.SPIFFEID{
				TrustDomain: td.Name(),
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
						telemetry.SPIFFEID: spiffeid.RequireFromPath(td, agentPath).String(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.SPIFFEID:      "spiffe://example.org/spire/agent/agent-1",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to ban agent: unknown datastore error",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, 0)
			defer test.Cleanup()
			ctx := context.Background()

			node := &common.AttestedNode{
				SpiffeId:            spiffeid.RequireFromPath(td, agentPath).String(),
				AttestationDataType: "attestation-type",
				CertNotAfter:        100,
				NewCertNotAfter:     200,
				CertSerialNumber:    "1234",
				NewCertSerialNumber: "1235",
			}

			_, err := test.ds.CreateAttestedNode(ctx, node)
			require.NoError(t, err)
			test.ds.SetNextError(tt.dsError)

			banResp, err := test.client.BanAgent(ctx, &agentv1.BanAgentRequest{Id: tt.reqID})
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			test.ds.SetNextError(nil)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if tt.expectCode != codes.OK {
				require.Nil(t, banResp)

				attestedNode, err := test.ds.FetchAttestedNode(ctx, node.SpiffeId)
				require.NoError(t, err)
				require.NotNil(t, attestedNode)
				require.NotZero(t, attestedNode.CertSerialNumber)
				require.NotZero(t, attestedNode.NewCertSerialNumber)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, banResp)

			attestedNode, err := test.ds.FetchAttestedNode(ctx, idutil.RequireIDProtoString(tt.reqID))
			require.NoError(t, err)
			require.NotNil(t, attestedNode)

			node.CertSerialNumber = ""
			node.NewCertSerialNumber = ""
			spiretest.RequireProtoEqual(t, node, attestedNode)
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
		req        *agentv1.DeleteAgentRequest
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/node1",
					},
				},
			},
			req: &agentv1.DeleteAgentRequest{
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
						logrus.ErrorKey: "trust domain is missing",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid agent ID: trust domain is missing",
					},
				},
			},
			code: codes.InvalidArgument,
			err:  "invalid agent ID: trust domain is missing",
			req: &agentv1.DeleteAgentRequest{
				Id: &types.SPIFFEID{
					TrustDomain: "",
					Path:        "/spire/agent/node1",
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.SPIFFEID:      "spiffe://example.org/spire/agent/notfound",
						telemetry.StatusCode:    "NotFound",
						telemetry.StatusMessage: "agent not found",
					},
				},
			},
			code: codes.NotFound,
			err:  "agent not found",
			req: &agentv1.DeleteAgentRequest{
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
						logrus.ErrorKey: "\"spiffe://example.org/host\" is not an agent in trust domain \"example.org\"; path is not in the agent namespace",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid agent ID: \"spiffe://example.org/host\" is not an agent in trust domain \"example.org\"; path is not in the agent namespace",
					},
				},
			},
			code: codes.InvalidArgument,
			err:  "invalid agent ID: \"spiffe://example.org/host\" is not an agent in trust domain \"example.org\"; path is not in the agent namespace",
			req: &agentv1.DeleteAgentRequest{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "/host",
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: `invalid agent ID: "spiffe://another.org/spire/agent/node1" is not a member of trust domain "example.org"`,
					},
				},
			},
			code: codes.InvalidArgument,
			err:  `invalid agent ID: "spiffe://another.org/spire/agent/node1" is not a member of trust domain "example.org"`,
			req: &agentv1.DeleteAgentRequest{
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.SPIFFEID:      "spiffe://example.org/spire/agent/node1",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to remove agent: some error",
					},
				},
			},
			req: &agentv1.DeleteAgentRequest{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "/spire/agent/node1",
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, 0)
			defer test.Cleanup()

			_, err := test.ds.CreateAttestedNode(ctx, node1)
			require.NoError(t, err)
			test.ds.SetNextError(tt.dsError)

			resp, err := test.client.DeleteAgent(ctx, tt.req)

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if err != nil {
				require.Nil(t, resp)
				spiretest.RequireGRPCStatus(t, err, tt.code, tt.err)

				// Verify node was not deleted
				attestedNode, err := test.ds.FetchAttestedNode(ctx, node1.SpiffeId)
				require.NoError(t, err)
				require.NotNil(t, attestedNode)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			id := idutil.RequireIDFromProto(tt.req.Id)

			attestedNode, err := test.ds.FetchAttestedNode(ctx, id.String())
			require.NoError(t, err)
			require.Nil(t, attestedNode)
		})
	}
}

func TestGetAgent(t *testing.T) {
	for _, tt := range []struct {
		name    string
		req     *agentv1.GetAgentRequest
		agent   *types.Agent
		code    codes.Code
		err     string
		logs    []spiretest.LogEntry
		dsError error
	}{
		{
			name:  "success agent-1",
			req:   &agentv1.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-1"}},
			agent: expectedAgents[agent1],
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/agent-1",
					},
				},
			},
		},
		{
			name:  "success agent-2",
			req:   &agentv1.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-2"}},
			agent: expectedAgents[agent2],
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/agent-2",
					},
				},
			},
		},
		{
			name: "success - with mask",
			req: &agentv1.GetAgentRequest{
				Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-1"},
				OutputMask: &types.AgentMask{
					AttestationType:      true,
					X509SvidExpiresAt:    true,
					X509SvidSerialNumber: true,
				},
			},
			agent: &types.Agent{
				Id:                   expectedAgents[agent1].Id,
				AttestationType:      expectedAgents[agent1].AttestationType,
				X509SvidExpiresAt:    expectedAgents[agent1].X509SvidExpiresAt,
				X509SvidSerialNumber: expectedAgents[agent1].X509SvidSerialNumber,
			},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/agent-1",
					},
				},
			},
		},
		{
			name: "success - with all false mask",
			req: &agentv1.GetAgentRequest{
				Id:         &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-1"},
				OutputMask: &types.AgentMask{},
			},
			agent: &types.Agent{
				Id: expectedAgents[agent1].Id,
			},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/agent-1",
					},
				},
			},
		},
		{
			name: "no SPIFFE ID",
			req:  &agentv1.GetAgentRequest{},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "request must specify SPIFFE ID",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid agent ID: request must specify SPIFFE ID",
					},
				},
			},
			err:  "request must specify SPIFFE ID",
			code: codes.InvalidArgument,
		},
		{
			name: "invalid SPIFFE ID",
			req:  &agentv1.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "invalid domain"}},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: invalid agent ID",
					Data: logrus.Fields{
						logrus.ErrorKey: "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "invalid agent ID: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
					},
				},
			},
			err:  "invalid agent ID: trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores",
			code: codes.InvalidArgument,
		},
		{
			name: "agent does not exist",
			req:  &agentv1.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/does-not-exist"}},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent not found",
					Data: logrus.Fields{
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/does-not-exist",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.SPIFFEID:      "spiffe://example.org/spire/agent/does-not-exist",
						telemetry.StatusCode:    "NotFound",
						telemetry.StatusMessage: "agent not found",
					},
				},
			},
			err:  "agent not found",
			code: codes.NotFound,
		},
		{
			name: "datastore error",
			req:  &agentv1.GetAgentRequest{Id: &types.SPIFFEID{TrustDomain: "example.org", Path: "/spire/agent/agent-1"}},
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch agent",
					Data: logrus.Fields{
						logrus.ErrorKey:    "datastore error",
						telemetry.SPIFFEID: "spiffe://example.org/spire/agent/agent-1",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.SPIFFEID:      "spiffe://example.org/spire/agent/agent-1",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to fetch agent: datastore error",
					},
				},
			},
			err:     "failed to fetch agent: datastore error",
			code:    codes.Internal,
			dsError: errors.New("datastore error"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, 0)
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
	agentIDType := &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"}

	defaultNode := &common.AttestedNode{
		SpiffeId:            agentID.String(),
		AttestationDataType: "t",
		CertNotAfter:        12345,
		CertSerialNumber:    "6789",
	}

	reattestableNode := cloneAttestedNode(defaultNode)
	reattestableNode.CanReattest = true

	// Create a test CSR with empty template
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, testKey)
	require.NoError(t, err)
	csrHash := api.HashByte(csr)

	renewingMessage := spiretest.LogEntry{
		Level:   logrus.InfoLevel,
		Message: "Renewing agent SVID",
	}

	malformedCsr := []byte("malformed csr")
	_, malformedError := x509.ParseCertificateRequest(malformedCsr)
	require.Error(t, malformedError)
	malformedCsrHash := api.HashByte(malformedCsr)

	for _, tt := range []struct {
		name string

		dsError        []error
		createNode     *common.AttestedNode
		agentSVIDTTL   time.Duration
		expectLogs     []spiretest.LogEntry
		failCallerID   bool
		failSigning    bool
		req            *agentv1.RenewAgentRequest
		expectCode     codes.Code
		expectMsg      string
		expectDetail   proto.Message
		rateLimiterErr error
	}{
		{
			name:         "success",
			createNode:   cloneAttestedNode(defaultNode),
			agentSVIDTTL: 42 * time.Minute,
			expectLogs: []spiretest.LogEntry{
				renewingMessage,
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
						telemetry.Csr:    csrHash,
					},
				},
			},
			req: &agentv1.RenewAgentRequest{
				Params: &agentv1.AgentX509SVIDParams{
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Unknown",
						telemetry.StatusMessage: "rejecting request due to renew agent rate limiting: rate limit fails",
						telemetry.Csr:           csrHash,
					},
				},
			},
			req: &agentv1.RenewAgentRequest{
				Params: &agentv1.AgentX509SVIDParams{
					Csr: csr,
				},
			},
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "caller ID missing from request context",
					},
				},
			},
			req:          &agentv1.RenewAgentRequest{},
			failCallerID: true,
			expectCode:   codes.Internal,
			expectMsg:    "caller ID missing from request context",
		},
		{
			name: "no attested node",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent not found",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.Csr:           csrHash,
						telemetry.StatusCode:    "NotFound",
						telemetry.StatusMessage: "agent not found",
					},
				},
			},
			req: &agentv1.RenewAgentRequest{
				Params: &agentv1.AgentX509SVIDParams{
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "missing CSR",
					},
				},
			},
			req: &agentv1.RenewAgentRequest{
				Params: &agentv1.AgentX509SVIDParams{},
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
						logrus.ErrorKey: malformedError.Error(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.Csr:           malformedCsrHash,
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: fmt.Sprintf("failed to parse CSR: %v", malformedError.Error()),
					},
				},
			},
			req: &agentv1.RenewAgentRequest{
				Params: &agentv1.AgentX509SVIDParams{
					Csr: malformedCsr,
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "params cannot be nil",
					},
				},
			},
			req:        &agentv1.RenewAgentRequest{},
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.Csr:           csrHash,
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to sign X509 SVID: X509 CA is not available for signing",
					},
				},
			},
			failSigning: true,
			req: &agentv1.RenewAgentRequest{
				Params: &agentv1.AgentX509SVIDParams{
					Csr: csr,
				},
			},
			expectCode: codes.Internal,
			expectMsg:  "failed to sign X509 SVID: X509 CA is not available for signing",
		},
		{
			name:       "failed to fetch attested node",
			createNode: cloneAttestedNode(defaultNode),
			dsError: []error{
				errors.New("some error"),
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch agent",
					Data: logrus.Fields{
						logrus.ErrorKey: "some error",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.Csr:           csrHash,
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to fetch agent: some error",
					},
				},
			},
			req: &agentv1.RenewAgentRequest{
				Params: &agentv1.AgentX509SVIDParams{
					Csr: csr,
				},
			},
			expectCode: codes.Internal,
			expectMsg:  "failed to fetch agent: some error",
		},
		{
			name:       "can reattest instead",
			createNode: reattestableNode,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.Csr:           csrHash,
						telemetry.StatusCode:    "PermissionDenied",
						telemetry.StatusMessage: "agent must reattest instead of renew",
					},
				},
			},
			req: &agentv1.RenewAgentRequest{
				Params: &agentv1.AgentX509SVIDParams{
					Csr: csr,
				},
			},
			expectCode:   codes.PermissionDenied,
			expectMsg:    "agent must reattest instead of renew",
			expectDetail: &types.PermissionDeniedDetails{Reason: types.PermissionDeniedDetails_AGENT_MUST_REATTEST},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test
			test := setupServiceTest(t, tt.agentSVIDTTL)
			defer test.Cleanup()

			if tt.createNode != nil {
				_, err := test.ds.CreateAttestedNode(ctx, tt.createNode)
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

			// Verify non-default agent TTL if set
			if tt.agentSVIDTTL != 0 {
				expiredAt = now.Add(tt.agentSVIDTTL)
			}

			// Send param message
			resp, err := test.client.RenewAgent(ctx, tt.req)
			spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
			st := status.Convert(err)
			if tt.expectDetail == nil {
				require.Empty(t, st.Details())
			} else {
				require.Len(t, st.Details(), 1)
				spiretest.RequireProtoEqual(t, tt.expectDetail, st.Details()[0].(proto.Message))
			}

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
			updatedNode, err := test.ds.FetchAttestedNode(ctx, agentID.String())
			require.NoError(t, err)
			require.NotNil(t, updatedNode)
			expectedNode := tt.createNode
			expectedNode.NewCertNotAfter = x509Svid.NotAfter.Unix()
			expectedNode.NewCertSerialNumber = x509Svid.SerialNumber.String()
			spiretest.AssertProtoEqual(t, expectedNode, updatedNode)

			// No logs expected
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
		})
	}
}

func TestPostStatus(t *testing.T) {
	test := setupServiceTest(t, 0)

	resp, err := test.client.PostStatus(context.Background(), &agentv1.PostStatusRequest{})
	require.Nil(t, resp)
	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "unimplemented")
}

func TestCreateJoinToken(t *testing.T) {
	for _, tt := range []struct {
		name          string
		request       *agentv1.CreateJoinTokenRequest
		expectLogs    []spiretest.LogEntry
		expectResults *types.JoinToken
		err           string
		code          codes.Code
		dsError       error
	}{
		{
			name: "Success Basic Create Join Token",
			request: &agentv1.CreateJoinTokenRequest{
				Ttl: 1000,
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
						telemetry.TTL:    "1000",
					},
				},
			},
		},
		{
			name: "Success Custom Value Join Token",
			request: &agentv1.CreateJoinTokenRequest{
				Ttl:   1000,
				Token: "token goes here",
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
						telemetry.TTL:    "1000",
					},
				},
			},
		},
		{
			name: "Fail Negative Ttl",
			request: &agentv1.CreateJoinTokenRequest{
				Ttl: -1000,
			},
			err:  "ttl is required, you must provide one",
			code: codes.InvalidArgument,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: ttl is required, you must provide one",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "ttl is required, you must provide one",
					},
				},
			},
		},
		{
			name: "Fail Datastore Error",
			err:  "failed to create token: datastore broken",
			request: &agentv1.CreateJoinTokenRequest{
				Ttl: 1000,
			},
			dsError: errors.New("datastore broken"),
			code:    codes.Internal,
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to create token",
					Data: logrus.Fields{
						logrus.ErrorKey: "datastore broken",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to create token: datastore broken",
						telemetry.TTL:           "1000",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, 0)
			test.ds.SetNextError(tt.dsError)

			result, err := test.client.CreateJoinToken(context.Background(), tt.request)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)

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
	test := setupServiceTest(t, 0)

	_, err := test.client.CreateJoinToken(context.Background(), &agentv1.CreateJoinTokenRequest{
		Ttl:     1000,
		AgentId: &types.SPIFFEID{TrustDomain: "badtd.org", Path: "/invalid"},
	})
	require.Error(t, err)
	spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, `invalid agent ID: "spiffe://badtd.org/invalid" is not a member of trust domain "example.org"`)
	expectLogs := []spiretest.LogEntry{
		{
			Level:   logrus.ErrorLevel,
			Message: "Invalid argument: invalid agent ID",
			Data: logrus.Fields{
				logrus.ErrorKey: `"spiffe://badtd.org/invalid" is not a member of trust domain "example.org"`,
			},
		},
		{
			Level:   logrus.InfoLevel,
			Message: "API accessed",
			Data: logrus.Fields{
				telemetry.Status:        "error",
				telemetry.Type:          "audit",
				telemetry.StatusCode:    "InvalidArgument",
				telemetry.StatusMessage: `invalid agent ID: "spiffe://badtd.org/invalid" is not a member of trust domain "example.org"`,
				telemetry.TTL:           "1000",
			},
		},
	}
	spiretest.AssertLogs(t, test.logHook.AllEntries(), expectLogs)
	test.logHook.Reset()

	token, err := test.client.CreateJoinToken(context.Background(), &agentv1.CreateJoinTokenRequest{
		Ttl:     1000,
		AgentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/valid"},
	})
	require.NoError(t, err)
	spiretest.RequireGRPCStatusContains(t, err, codes.OK, "")
	expectLogs = []spiretest.LogEntry{
		{
			Level:   logrus.InfoLevel,
			Message: "API accessed",
			Data: logrus.Fields{
				telemetry.Status:   "success",
				telemetry.Type:     "audit",
				telemetry.SPIFFEID: "spiffe://example.org/valid",
				telemetry.TTL:      "1000",
			},
		},
	}
	spiretest.AssertLogs(t, test.logHook.AllEntries(), expectLogs)

	listEntries, err := test.ds.ListRegistrationEntries(context.Background(), &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)
	require.Equal(t, "spiffe://example.org/valid", listEntries.Entries[0].SpiffeId)
	require.Equal(t, "spiffe://example.org/spire/agent/join_token/"+token.Value, listEntries.Entries[0].ParentId)
	require.Equal(t, "spiffe://example.org/spire/agent/join_token/"+token.Value, listEntries.Entries[0].Selectors[0].Value)
}

func TestAttestAgent(t *testing.T) {
	testCsr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, testKey)
	require.NoError(t, err)

	_, expectedCsrErr := x509.ParseCertificateRequest([]byte("not a csr"))
	require.Error(t, expectedCsrErr)

	for _, tt := range []struct {
		name              string
		retry             bool
		request           *agentv1.AttestAgentRequest
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
			request:    &agentv1.AttestAgentRequest{},
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "malformed param: missing params",
					},
				},
			},
		},

		{
			name: "empty attestation data",
			request: &agentv1.AttestAgentRequest{
				Step: &agentv1.AttestAgentRequest_Params_{
					Params: &agentv1.AttestAgentRequest_Params{},
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "malformed param: missing attestation data",
					},
				},
			},
		},

		{
			name: "missing parameters",
			request: &agentv1.AttestAgentRequest{
				Step: &agentv1.AttestAgentRequest_Params_{
					Params: &agentv1.AttestAgentRequest_Params{
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "malformed param: missing X509-SVID parameters",
					},
				},
			},
		},

		{
			name: "missing attestation data type",
			request: &agentv1.AttestAgentRequest{
				Step: &agentv1.AttestAgentRequest_Params_{
					Params: &agentv1.AttestAgentRequest_Params{
						Data: &types.AttestationData{},
						Params: &agentv1.AgentX509SVIDParams{
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "malformed param: missing attestation data type",
					},
				},
			},
		},

		{
			name: "missing csr",
			request: &agentv1.AttestAgentRequest{
				Step: &agentv1.AttestAgentRequest_Params_{
					Params: &agentv1.AttestAgentRequest_Params{
						Data: &types.AttestationData{
							Type: "foo type",
						},
						Params: &agentv1.AgentX509SVIDParams{},
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "malformed param: missing CSR",
					},
				},
			},
		},

		{
			name:           "rate limit fails",
			request:        &agentv1.AttestAgentRequest{},
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Unknown",
						telemetry.StatusMessage: "rejecting request due to attest agent rate limiting: rate limit fails",
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "failed to attest: join token does not exist or has already been used",
						telemetry.NodeAttestorType: "join_token",
					},
				},
			},
		},

		{
			name:       "attest with join token",
			request:    getAttestAgentRequest("join_token", []byte("test_token"), testCsr),
			expectedID: spiffeid.RequireFromPath(td, "/spire/agent/join_token/test_token"),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Agent attestation request completed",
					Data: logrus.Fields{
						telemetry.AgentID:          "spiffe://example.org/spire/agent/join_token/test_token",
						telemetry.NodeAttestorType: "join_token",
						telemetry.Address:          "",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/join_token/test_token",
						telemetry.NodeAttestorType: "join_token",
					},
				},
			},
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
						telemetry.AgentID:          spiffeid.RequireFromPath(td, "/spire/agent/join_token/banned_token").String(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "PermissionDenied",
						telemetry.StatusMessage:    "failed to attest: agent is banned",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/join_token/banned_token",
						telemetry.NodeAttestorType: "join_token",
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "join token expired",
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
					Level:   logrus.InfoLevel,
					Message: "Agent attestation request completed",
					Data: logrus.Fields{
						telemetry.Address:          "",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/join_token/test_token",
						telemetry.NodeAttestorType: "join_token",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.AgentID:          "spiffe://example.org/spire/agent/join_token/test_token",
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.NodeAttestorType: "join_token",
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to attest: join token does not exist or has already been used",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    "failed to attest: join token does not exist or has already been used",
						telemetry.NodeAttestorType: "join_token",
					},
				},
			},
		},

		{
			name:       "attest with result",
			request:    getAttestAgentRequest("test_type", []byte("payload_with_result"), testCsr),
			expectedID: spiffeid.RequireFromPath(td, "/spire/agent/test_type/id_with_result"),
			expectedSelectors: []*common.Selector{
				{Type: "test_type", Value: "result"},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Agent attestation request completed",
					Data: logrus.Fields{
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_with_result",
						telemetry.NodeAttestorType: "test_type",
						telemetry.Address:          "",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_with_result",
						telemetry.NodeAttestorType: "test_type",
					},
				},
			},
		},

		{
			name:       "attest with result twice",
			retry:      true,
			request:    getAttestAgentRequest("test_type", []byte("payload_with_result"), testCsr),
			expectedID: spiffeid.RequireFromPath(td, "/spire/agent/test_type/id_with_result"),
			expectedSelectors: []*common.Selector{
				{Type: "test_type", Value: "result"},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Agent attestation request completed",
					Data: logrus.Fields{
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_with_result",
						telemetry.NodeAttestorType: "test_type",
						telemetry.Address:          "",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_with_result",
						telemetry.NodeAttestorType: "test_type",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "Agent attestation request completed",
					Data: logrus.Fields{
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_with_result",
						telemetry.NodeAttestorType: "test_type",
						telemetry.Address:          "",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_with_result",
						telemetry.NodeAttestorType: "test_type",
					},
				},
			},
		},

		{
			name:       "attest with challenge",
			request:    getAttestAgentRequest("test_type", []byte("payload_with_challenge"), testCsr),
			expectedID: spiffeid.RequireFromPath(td, "/spire/agent/test_type/id_with_challenge"),
			expectedSelectors: []*common.Selector{
				{Type: "test_type", Value: "challenge"},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Agent attestation request completed",
					Data: logrus.Fields{
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_with_challenge",
						telemetry.NodeAttestorType: "test_type",
						telemetry.Address:          "",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_with_challenge",
						telemetry.NodeAttestorType: "test_type",
					},
				},
			},
		},

		{
			name:       "attest already attested",
			request:    getAttestAgentRequest("test_type", []byte("payload_attested_before"), testCsr),
			expectedID: spiffeid.RequireFromPath(td, "/spire/agent/test_type/id_attested_before"),
			expectedSelectors: []*common.Selector{
				{Type: "test_type", Value: "attested_before"},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Agent attestation request completed",
					Data: logrus.Fields{
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_attested_before",
						telemetry.NodeAttestorType: "test_type",
						telemetry.Address:          "",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_attested_before",
						telemetry.NodeAttestorType: "test_type",
					},
				},
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
						telemetry.AgentID:          spiffeid.RequireFromPath(td, "/spire/agent/test_type/id_banned").String(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "PermissionDenied",
						telemetry.StatusMessage:    "failed to attest: agent is banned",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_banned",
						telemetry.NodeAttestorType: "test_type",
					},
				},
			},
		},

		{
			name:       "attest with bad attestor",
			request:    getAttestAgentRequest("bad_type", []byte("payload_with_result"), testCsr),
			expectCode: codes.FailedPrecondition,
			expectMsg:  "error getting node attestor: could not find node attestor type \"bad_type\"",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Error getting node attestor",
					Data: logrus.Fields{
						logrus.ErrorKey:            "could not find node attestor type \"bad_type\"",
						telemetry.NodeAttestorType: "bad_type",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "FailedPrecondition",
						telemetry.StatusMessage:    "error getting node attestor: could not find node attestor type \"bad_type\"",
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
						telemetry.AgentID:          spiffeid.RequireFromPath(td, "/spire/agent/test_type/id_with_result").String(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "InvalidArgument",
						telemetry.StatusMessage:    fmt.Sprintf("failed to parse CSR: %v", expectedCsrErr.Error()),
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_with_result",
						telemetry.NodeAttestorType: "test_type",
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to fetch join token: some error",
						telemetry.NodeAttestorType: "join_token",
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
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to delete join token: some error",
						telemetry.NodeAttestorType: "join_token",
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
						telemetry.AgentID:          spiffeid.RequireFromPath(td, "/spire/agent/join_token/test_token").String(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to fetch agent: some error",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/join_token/test_token",
						telemetry.NodeAttestorType: "join_token",
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
					Level:   logrus.ErrorLevel,
					Message: "Failed to update selectors",

					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
						logrus.ErrorKey:            "some error",
						telemetry.AgentID:          spiffeid.RequireFromPath(td, "/spire/agent/join_token/test_token").String(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to update selectors: some error",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/join_token/test_token",
						telemetry.NodeAttestorType: "join_token",
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
					Level:   logrus.ErrorLevel,
					Message: "Failed to create attested agent",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "join_token",
						logrus.ErrorKey:            "some error",
						telemetry.AgentID:          spiffeid.RequireFromPath(td, "/spire/agent/join_token/test_token").String(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to create attested agent: some error",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/join_token/test_token",
						telemetry.NodeAttestorType: "join_token",
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
						telemetry.AgentID:          spiffeid.RequireFromPath(td, "/spire/agent/test_type/id_attested_before").String(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "failed to update attested agent: some error",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_attested_before",
						telemetry.NodeAttestorType: "test_type",
					},
				},
			},
		},
		{
			name:       "nodeattestor returns server ID",
			request:    getAttestAgentRequest("test_type", []byte("payload_return_server_id"), testCsr),
			expectCode: codes.Internal,
			expectMsg:  "agent ID cannot collide with the server ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent ID cannot collide with the server ID",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "test_type",
						telemetry.AgentID:          spiffeid.RequireFromPath(td, "/spire/server").String(),
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "error",
						telemetry.Type:             "audit",
						telemetry.StatusCode:       "Internal",
						telemetry.StatusMessage:    "agent ID cannot collide with the server ID",
						telemetry.AgentID:          "spiffe://example.org/spire/server",
						telemetry.NodeAttestorType: "test_type",
					},
				},
			},
		},
		{
			name:       "nodeattestor returns ID outside of its namespace",
			request:    getAttestAgentRequest("test_type", []byte("payload_return_id_outside_namespace"), testCsr),
			expectedID: spiffeid.RequireFromPath(td, "/id_outside_namespace"),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "The node attestor produced an invalid agent ID; future releases will enforce that agent IDs are within the reserved agent namesepace for the node attestor",
					Data: logrus.Fields{
						telemetry.NodeAttestorType: "test_type",
						telemetry.AgentID:          spiffeid.RequireFromPath(td, "/id_outside_namespace").String(),
						logrus.ErrorKey:            `"spiffe://example.org/id_outside_namespace" is not in the agent namespace for attestor "test_type"`,
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "Agent attestation request completed",
					Data: logrus.Fields{
						telemetry.AgentID:          "spiffe://example.org/id_outside_namespace",
						telemetry.NodeAttestorType: "test_type",
						telemetry.Address:          "",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.AgentID:          "spiffe://example.org/id_outside_namespace",
						telemetry.NodeAttestorType: "test_type",
					},
				},
			},
		},
		{
			name:       "duplicate selectors",
			request:    getAttestAgentRequest("test_type", []byte("payload_selector_dups"), testCsr),
			expectedID: spiffeid.RequireFromPath(td, "/spire/agent/test_type/id_selector_dups"),
			expectedSelectors: []*common.Selector{
				{Type: "test_type", Value: "A"},
				{Type: "test_type", Value: "B"},
				{Type: "test_type", Value: "C"},
				{Type: "test_type", Value: "D"},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "Agent attestation request completed",
					Data: logrus.Fields{
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_selector_dups",
						telemetry.NodeAttestorType: "test_type",
						telemetry.Address:          "",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:           "success",
						telemetry.Type:             "audit",
						telemetry.AgentID:          "spiffe://example.org/spire/agent/test_type/id_selector_dups",
						telemetry.NodeAttestorType: "test_type",
					},
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// setup
			test := setupServiceTest(t, 0)
			defer func() {
				// Since this is a bidirectional streaming API, it's possible
				// that the server is still emitting auditing logs even though
				// we've received the last response from the server. In order
				// to avoid racing on the log hook, clean up the test (to make
				// sure the server has shut down) before checking for log
				// entries.
				test.Cleanup()

				// Scrub out client address before comparing logs.
				for _, e := range test.logHook.AllEntries() {
					if _, ok := e.Data[telemetry.Address]; ok {
						e.Data[telemetry.Address] = ""
					}
				}

				spiretest.AssertLogsAnyOrder(t, test.logHook.AllEntries(), tt.expectLogs)
			}()

			ctx := t.Context()

			test.setupAttestor(t)
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
			default:
				require.NotNil(t, result)
				test.assertAttestAgentResult(t, tt.expectedID, result)
				test.assertAgentWasStored(t, tt.expectedID.String(), tt.expectedSelectors)
			}
		})
	}
}

type serviceTest struct {
	client       agentv1.AgentClient
	done         func()
	ds           *fakedatastore.DataStore
	ca           *fakeserverca.CA
	cat          *fakeservercatalog.Catalog
	clk          clock.Clock
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

func setupServiceTest(t *testing.T, agentSVIDTTL time.Duration) *serviceTest {
	ca := fakeserverca.New(t, td, &fakeserverca.Options{
		AgentSVIDTTL: agentSVIDTTL,
	})
	ds := fakedatastore.New(t)
	cat := fakeservercatalog.New()
	clk := clock.NewMock(t)

	service := agent.New(agent.Config{
		ServerCA:    ca,
		DataStore:   ds,
		TrustDomain: td,
		Clock:       clk,
		Catalog:     cat,
	})

	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	rateLimiter := &fakeRateLimiter{}

	test := &serviceTest{
		ca:          ca,
		ds:          ds,
		cat:         cat,
		clk:         clk,
		logHook:     logHook,
		rateLimiter: rateLimiter,
	}

	overrideContext := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		ctx = rpccontext.WithRateLimiter(ctx, rateLimiter)
		if test.withCallerID {
			ctx = rpccontext.WithCallerID(ctx, agentID)
		}
		return ctx
	}

	server := grpctest.StartServer(t, func(s grpc.ServiceRegistrar) {
		agent.RegisterService(s, service)
	},
		grpctest.OverrideContext(overrideContext),
		grpctest.Middleware(middleware.WithAuditLog(false)),
	)

	conn := server.NewGRPCClient(t)

	test.client = agentv1.NewAgentClient(conn)
	test.done = server.Stop

	return test
}

func (s *serviceTest) setupAttestor(t *testing.T) {
	attestorConfig := fakeservernodeattestor.Config{
		ReturnLiteral: true,
		Payloads: map[string]string{
			"payload_attested_before":             "spiffe://example.org/spire/agent/test_type/id_attested_before",
			"payload_with_challenge":              "spiffe://example.org/spire/agent/test_type/id_with_challenge",
			"payload_with_result":                 "spiffe://example.org/spire/agent/test_type/id_with_result",
			"payload_banned":                      "spiffe://example.org/spire/agent/test_type/id_banned",
			"payload_return_server_id":            "spiffe://example.org/spire/server",
			"payload_return_id_outside_namespace": "spiffe://example.org/id_outside_namespace",
			"payload_selector_dups":               "spiffe://example.org/spire/agent/test_type/id_selector_dups",
		},
		Selectors: map[string][]string{
			"spiffe://example.org/spire/agent/test_type/id_with_result":     {"result"},
			"spiffe://example.org/spire/agent/test_type/id_attested_before": {"attested_before"},
			"spiffe://example.org/spire/agent/test_type/id_with_challenge":  {"challenge"},
			"spiffe://example.org/spire/agent/test_type/id_banned":          {"banned"},
			"spiffe://example.org/spire/agent/test_type/id_selector_dups":   {"A", "B", "C", "A", "D"},
		},
		Challenges: map[string][]string{
			"id_with_challenge": {"challenge_response"},
		},
	}

	fakeNodeAttestor := fakeservernodeattestor.New(t, "test_type", attestorConfig)
	s.cat.SetNodeAttestor(fakeNodeAttestor)
}

func (s *serviceTest) setupNodes(ctx context.Context, t *testing.T) {
	node := &common.AttestedNode{
		AttestationDataType: "test_type",
		SpiffeId:            spiffeid.RequireFromPath(td, "/spire/agent/test_type/id_attested_before").String(),
		CertSerialNumber:    "test_serial_number",
	}
	_, err := s.ds.CreateAttestedNode(ctx, node)
	require.NoError(t, err)

	node = &common.AttestedNode{
		AttestationDataType: "test_type",
		SpiffeId:            spiffeid.RequireFromPath(td, "/spire/agent/test_type/id_banned").String(),
		CertNotAfter:        0,
		CertSerialNumber:    "",
	}
	_, err = s.ds.CreateAttestedNode(ctx, node)
	require.NoError(t, err)

	node = &common.AttestedNode{
		AttestationDataType: "join_token",
		SpiffeId:            spiffeid.RequireFromPath(td, "/spire/agent/join_token/banned_token").String(),
		CertNotAfter:        0,
		CertSerialNumber:    "",
	}
	_, err = s.ds.CreateAttestedNode(ctx, node)
	require.NoError(t, err)
}

func (s *serviceTest) setupJoinTokens(ctx context.Context, t *testing.T) {
	now := s.clk.Now()
	err := s.ds.CreateJoinToken(ctx, &datastore.JoinToken{
		Token:  "test_token",
		Expiry: now.Add(time.Second * 600),
	})
	require.NoError(t, err)

	err = s.ds.CreateJoinToken(ctx, &datastore.JoinToken{
		Token:  "banned_token",
		Expiry: now.Add(time.Second * 600),
	})
	require.NoError(t, err)

	err = s.ds.CreateJoinToken(ctx, &datastore.JoinToken{
		Token:  "expired_token",
		Expiry: now.Add(-time.Second * 600),
	})
	require.NoError(t, err)
}

func (s *serviceTest) createTestNodes(ctx context.Context, t *testing.T) {
	for _, testNode := range testNodes {
		// create the test node
		_, err := s.ds.CreateAttestedNode(ctx, testNode)
		require.NoError(t, err)

		// set selectors to the test node
		err = s.ds.SetNodeSelectors(ctx, testNode.SpiffeId, testNodeSelectors[testNode.SpiffeId])
		require.NoError(t, err)
	}
}

func (s *serviceTest) assertAttestAgentResult(t *testing.T, expectedID spiffeid.ID, result *agentv1.AttestAgentResponse_Result) {
	now := s.ca.Clock().Now().UTC()
	expiredAt := now.Add(s.ca.X509SVIDTTL())

	require.NotNil(t, result.Svid)
	expectedIDType := &types.SPIFFEID{TrustDomain: expectedID.TrustDomain().Name(), Path: expectedID.Path()}
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
	attestedAgent, err := s.ds.FetchAttestedNode(ctx, expectedID)
	require.NoError(t, err)
	require.NotNil(t, attestedAgent)
	require.Equal(t, expectedID, attestedAgent.SpiffeId)

	agentSelectors, err := s.ds.GetNodeSelectors(ctx, expectedID, datastore.RequireCurrent)
	require.NoError(t, err)
	require.EqualValues(t, expectedSelectors, agentSelectors)
}

type fakeRateLimiter struct {
	count int
	err   error
}

func (f *fakeRateLimiter) RateLimit(_ context.Context, count int) error {
	if f.count != count {
		return fmt.Errorf("rate limiter got %d but expected %d", count, f.count)
	}

	return f.err
}

func cloneAttestedNode(aNode *common.AttestedNode) *common.AttestedNode {
	return proto.Clone(aNode).(*common.AttestedNode)
}

func getAttestAgentRequest(attType string, payload []byte, csr []byte) *agentv1.AttestAgentRequest {
	return &agentv1.AttestAgentRequest{
		Step: &agentv1.AttestAgentRequest_Params_{
			Params: &agentv1.AttestAgentRequest_Params{
				Data: &types.AttestationData{
					Type:    attType,
					Payload: payload,
				},
				Params: &agentv1.AgentX509SVIDParams{
					Csr: csr,
				},
			},
		},
	}
}

func attest(t *testing.T, stream agentv1.Agent_AttestAgentClient, request *agentv1.AttestAgentRequest) (*agentv1.AttestAgentResponse_Result, error) {
	var result *agentv1.AttestAgentResponse_Result

	for {
		// send
		err := stream.Send(request)
		if !errors.Is(err, io.EOF) {
			require.NoError(t, err)
		}

		// recv
		resp, err := stream.Recv()
		challenge := resp.GetChallenge()
		result = resp.GetResult()

		if challenge != nil {
			// build new request to be sent
			request = &agentv1.AttestAgentRequest{
				Step: &agentv1.AttestAgentRequest_ChallengeResponse{
					ChallengeResponse: challenge,
				},
			}

			continue
		}
		return result, err
	}
}
