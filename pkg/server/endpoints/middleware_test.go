package endpoints

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/cache/entrycache"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type testEntries struct {
	nodeAliasEntries []*types.Entry
	workloadEntries  []*types.Entry
}

func TestAuthorizedEntryFetcherWithFullCache(t *testing.T) {
	ctx := context.Background()
	log, _ := test.NewNullLogger()
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)

	e := createAuthorizedEntryTestData(t, ds)
	expectedNodeAliasEntries := e.nodeAliasEntries
	expectedWorkloadEntries := e.workloadEntries[:len(e.workloadEntries)-1]
	expectedEntries := make([]*types.Entry, 0, len(expectedNodeAliasEntries)+len(expectedWorkloadEntries))
	expectedEntries = append(expectedEntries, expectedNodeAliasEntries...)
	expectedEntries = append(expectedEntries, expectedWorkloadEntries...)

	buildCache := func(context.Context) (entrycache.Cache, error) {
		entryMap := map[spiffeid.ID][]*types.Entry{
			agentID: expectedEntries,
		}

		return newStaticEntryCache(entryMap), nil
	}

	pruneEventsFn := func(context.Context, time.Duration) error {
		return nil
	}

	f, err := NewAuthorizedEntryFetcherWithFullCache(ctx, buildCache, pruneEventsFn, log, clk, defaultCacheReloadInterval, defaultPruneEventsOlderThan)
	require.NoError(t, err)

	entries, err := f.FetchAuthorizedEntries(context.Background(), agentID)
	assert.NoError(t, err)
	assert.ElementsMatch(t, expectedEntries, entries)
}

func TestAgentAuthorizer(t *testing.T) {
	ca := testca.New(t, testTD)
	agentSVID := ca.CreateX509SVID(agentID).Certificates[0]

	for _, tt := range []struct {
		name           string
		failFetch      bool
		failUpdate     bool
		node           *common.AttestedNode
		time           time.Time
		expectedCode   codes.Code
		expectedMsg    string
		expectedReason types.PermissionDeniedDetails_Reason
		expectedLogs   []spiretest.LogEntry
		expectedNode   *common.AttestedNode
	}{
		{
			name: "authorized",
			node: &common.AttestedNode{
				SpiffeId:         agentID.String(),
				CertSerialNumber: agentSVID.SerialNumber.String(),
			},
			expectedCode: codes.OK,
			expectedNode: &common.AttestedNode{
				SpiffeId:         agentID.String(),
				CertSerialNumber: agentSVID.SerialNumber.String(),
			},
		},
		{
			name:         "fail fetch",
			failFetch:    true,
			expectedCode: codes.Internal,
			expectedMsg:  "unable to look up agent information: fetch failed",
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Unable to look up agent information",
					Data: map[string]any{
						logrus.ErrorKey:      "fetch failed",
						telemetry.CallerID:   agentID.String(),
						telemetry.CallerAddr: "127.0.0.1",
					},
				},
			},
		},
		{
			name: "expired",
			time: agentSVID.NotAfter.Add(time.Second),
			node: &common.AttestedNode{
				SpiffeId:         agentID.String(),
				CertSerialNumber: agentSVID.SerialNumber.String(),
			},
			expectedCode:   codes.PermissionDenied,
			expectedMsg:    `agent "spiffe://domain.test/spire/agent/foo" SVID is expired`,
			expectedReason: types.PermissionDeniedDetails_AGENT_EXPIRED,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent SVID is expired",
					Data: map[string]any{
						telemetry.CallerID:   agentID.String(),
						telemetry.CallerAddr: "127.0.0.1",
					},
				},
			},
		},
		{
			name:           "no attested node",
			expectedCode:   codes.PermissionDenied,
			expectedMsg:    `agent "spiffe://domain.test/spire/agent/foo" is not attested`,
			expectedReason: types.PermissionDeniedDetails_AGENT_NOT_ATTESTED,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent is not attested",
					Data: map[string]any{
						telemetry.CallerID:   agentID.String(),
						telemetry.CallerAddr: "127.0.0.1",
					},
				},
			},
		},
		{
			name: "banned",
			node: &common.AttestedNode{
				SpiffeId: agentID.String(),
			},
			expectedCode:   codes.PermissionDenied,
			expectedMsg:    `agent "spiffe://domain.test/spire/agent/foo" is banned`,
			expectedReason: types.PermissionDeniedDetails_AGENT_BANNED,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent is banned",
					Data: map[string]any{
						telemetry.CallerID:   agentID.String(),
						telemetry.CallerAddr: "127.0.0.1",
					},
				},
			},
		},
		{
			name: "inactive SVID",
			node: &common.AttestedNode{
				SpiffeId:         agentID.String(),
				CertSerialNumber: "NEW",
			},
			expectedCode:   codes.PermissionDenied,
			expectedMsg:    fmt.Sprintf(`agent "spiffe://domain.test/spire/agent/foo" expected to have serial number "NEW"; has %q`, agentSVID.SerialNumber.String()),
			expectedReason: types.PermissionDeniedDetails_AGENT_NOT_ACTIVE,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent SVID is not active",
					Data: map[string]any{
						telemetry.CallerID:         agentID.String(),
						telemetry.CallerAddr:       "127.0.0.1",
						telemetry.SVIDSerialNumber: agentSVID.SerialNumber.String(),
						telemetry.SerialNumber:     "NEW",
					},
				},
			},
		},
		{
			name: "activates new SVID",
			node: &common.AttestedNode{
				SpiffeId:            agentID.String(),
				CertSerialNumber:    "CURRENT",
				NewCertSerialNumber: agentSVID.SerialNumber.String(),
				CanReattest:         true,
			},
			expectedCode: codes.OK,
			expectedNode: &common.AttestedNode{
				SpiffeId:            agentID.String(),
				CertSerialNumber:    agentSVID.SerialNumber.String(),
				NewCertSerialNumber: "",
				CanReattest:         true,
			},
		},
		{
			name: "failed to activate new SVID",
			node: &common.AttestedNode{
				SpiffeId:            agentID.String(),
				CertSerialNumber:    "CURRENT",
				NewCertSerialNumber: agentSVID.SerialNumber.String(),
			},
			failUpdate:   true,
			expectedCode: codes.Internal,
			expectedMsg:  `unable to activate the new agent SVID: update failed`,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "Unable to activate the new agent SVID",
					Data: map[string]any{
						telemetry.CallerID:         agentID.String(),
						telemetry.CallerAddr:       "127.0.0.1",
						telemetry.SVIDSerialNumber: agentSVID.SerialNumber.String(),
						telemetry.SerialNumber:     "CURRENT",
						telemetry.NewSerialNumber:  agentSVID.SerialNumber.String(),
						logrus.ErrorKey:            "update failed",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			ds := fakedatastore.New(t)

			if tt.node != nil {
				_, err := ds.CreateAttestedNode(context.Background(), tt.node)
				require.NoError(t, err)
			}

			ds.AppendNextError(func() error {
				if tt.failFetch {
					return errors.New("fetch failed")
				}
				return nil
			}())

			ds.AppendNextError(func() error {
				if tt.failUpdate {
					return errors.New("update failed")
				}
				return nil
			}())

			clk := clock.NewMock(t)
			if !tt.time.IsZero() {
				clk.Set(tt.time)
			}
			authorizer := AgentAuthorizer(ds, clk)
			ctx := context.Background()
			ctx = rpccontext.WithLogger(ctx, log.WithFields(logrus.Fields{
				telemetry.CallerAddr: "127.0.0.1",
				telemetry.CallerID:   agentID,
			}))
			err := authorizer.AuthorizeAgent(ctx, agentID, agentSVID)
			spiretest.RequireGRPCStatus(t, err, tt.expectedCode, tt.expectedMsg)
			spiretest.AssertLogs(t, hook.AllEntries(), tt.expectedLogs)

			switch tt.expectedCode {
			case codes.OK:
			case codes.PermissionDenied:
				// Assert that the expected permission denied reason is returned
				details := status.Convert(err).Details()
				require.Len(t, details, 1, "expecting permission denied detail")
				detail, ok := details[0].(proto.Message)
				require.True(t, ok, "detail is not a proto message")
				spiretest.RequireProtoEqual(t, &types.PermissionDeniedDetails{
					Reason: tt.expectedReason,
				}, detail)
				return
			case codes.Internal:
				return
			default:
				require.Fail(t, "unexpected error code")
			}

			attestedNode, err := ds.FetchAttestedNode(context.Background(), tt.node.SpiffeId)
			require.NoError(t, err)
			spiretest.RequireProtoEqual(t, tt.expectedNode, attestedNode)
		})
	}
}

func createEntry(t testing.TB, ds datastore.DataStore, entryIn *common.RegistrationEntry) *types.Entry {
	registrationEntry, err := ds.CreateRegistrationEntry(context.Background(), entryIn)
	require.NoError(t, err)
	entryOut, err := api.RegistrationEntryToProto(registrationEntry)
	require.NoError(t, err)
	return entryOut
}

func setNodeSelectors(t testing.TB, ds datastore.DataStore, id spiffeid.ID, selectors []*common.Selector) {
	err := ds.SetNodeSelectors(context.Background(), id.String(), selectors)
	require.NoError(t, err)
}

func createAttestedNode(t testing.TB, ds datastore.DataStore, node *common.AttestedNode) {
	_, err := ds.CreateAttestedNode(context.Background(), node)
	require.NoError(t, err)
}

func createAuthorizedEntryTestData(t testing.TB, ds datastore.DataStore) *testEntries {
	serverID := spiffeid.RequireFromPath(testTD, "/spire/server")
	anotherAgentID := spiffeid.RequireFromPath(testTD, "/spire/another-agent")
	nodeAliasID := spiffeid.RequireFromPath(testTD, "/node-alias")
	workload1ID := spiffeid.RequireFromPath(testTD, "/workload1")
	workload2ID := spiffeid.RequireFromPath(testTD, "/workload2")

	const testAttestationType = "test-nodeattestor"
	nonMatchingNode := &common.AttestedNode{
		SpiffeId:            anotherAgentID.String(),
		AttestationDataType: testAttestationType,
		CertSerialNumber:    "non-matching-serial",
		CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
	}

	matchingNode := &common.AttestedNode{
		SpiffeId:            agentID.String(),
		AttestationDataType: testAttestationType,
		CertSerialNumber:    "matching-serial",
		CertNotAfter:        time.Now().Add(24 * time.Hour).Unix(),
	}

	createAttestedNode(t, ds, nonMatchingNode)
	createAttestedNode(t, ds, matchingNode)

	nodeSel := []*common.Selector{
		{
			Type:  "node",
			Value: "value1",
		},
		{
			Type:  "node",
			Value: "value2",
		},
	}

	setNodeSelectors(t, ds, agentID, nodeSel)
	nodeAliasEntriesToCreate := []*common.RegistrationEntry{
		{
			ParentId: serverID.String(),
			SpiffeId: nodeAliasID.String(),
			Selectors: []*common.Selector{
				{
					Type:  "node",
					Value: "value1",
				},
			},
		},
	}

	nodeAliasEntries := make([]*types.Entry, len(nodeAliasEntriesToCreate))
	for i, e := range nodeAliasEntriesToCreate {
		nodeAliasEntries[i] = createEntry(t, ds, e)
	}

	workloadEntriesToCreate := []*common.RegistrationEntry{
		{
			ParentId: agentID.String(),
			SpiffeId: workload1ID.String(),
			Selectors: []*common.Selector{
				{
					Type:  "workload",
					Value: "value1",
				},
			},
		},
		{
			ParentId: agentID.String(),
			SpiffeId: workload2ID.String(),
			Selectors: []*common.Selector{
				{
					Type:  "workload",
					Value: "value2",
				},
			},
		},
		// Workload entry that should not be matched
		{
			ParentId: anotherAgentID.String(),
			SpiffeId: workload1ID.String(),
			Selectors: []*common.Selector{
				{
					Type:  "workload",
					Value: "value1",
				},
			},
		},
	}

	workloadEntries := make([]*types.Entry, len(workloadEntriesToCreate))
	for i, e := range workloadEntriesToCreate {
		workloadEntries[i] = createEntry(t, ds, e)
	}

	return &testEntries{
		nodeAliasEntries: nodeAliasEntries,
		workloadEntries:  workloadEntries,
	}
}
