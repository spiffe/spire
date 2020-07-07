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
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthorizedEntryFetcher(t *testing.T) {
	ds := fakedatastore.New(t)

	createEntry := func(entryIn *common.RegistrationEntry) *types.Entry {
		resp, err := ds.CreateRegistrationEntry(context.Background(), &datastore.CreateRegistrationEntryRequest{
			Entry: entryIn,
		})
		require.NoError(t, err)
		entryOut, err := api.RegistrationEntryToProto(resp.Entry)
		require.NoError(t, err)
		return entryOut
	}

	setNodeSelectors := func(id spiffeid.ID, selectors []*common.Selector) {
		_, err := ds.SetNodeSelectors(context.Background(), &datastore.SetNodeSelectorsRequest{
			Selectors: &datastore.NodeSelectors{
				SpiffeId:  id.String(),
				Selectors: selectors,
			},
		})
		require.NoError(t, err)
	}

	serverID := testTD.NewID("/spire/server")
	agentID := testTD.NewID("/spire/agent")
	anotherAgentID := testTD.NewID("/spire/another-agent")
	nodeAliasID := testTD.NewID("/node-alias")
	workload1ID := testTD.NewID("/workload1")
	workload2ID := testTD.NewID("/workload2")

	setNodeSelectors(agentID, []*common.Selector{
		{Type: "node", Value: "value1"},
		{Type: "node", Value: "value2"},
	})

	nodeAliasEntry := createEntry(&common.RegistrationEntry{
		ParentId:  serverID.String(),
		SpiffeId:  nodeAliasID.String(),
		Selectors: []*common.Selector{{Type: "node", Value: "value1"}},
	})

	workload1Entry := createEntry(&common.RegistrationEntry{
		ParentId:  agentID.String(),
		SpiffeId:  workload1ID.String(),
		Selectors: []*common.Selector{{Type: "workload", Value: "value1"}},
	})

	workload2Entry := createEntry(&common.RegistrationEntry{
		ParentId:  agentID.String(),
		SpiffeId:  workload2ID.String(),
		Selectors: []*common.Selector{{Type: "workload", Value: "value2"}},
	})

	// Create some other entry
	createEntry(&common.RegistrationEntry{
		ParentId:  anotherAgentID.String(),
		SpiffeId:  workload1ID.String(),
		Selectors: []*common.Selector{{Type: "workload", Value: "value1"}},
	})

	fetcher := AuthorizedEntryFetcher(ds)

	t.Run("success", func(t *testing.T) {
		ds.SetNextError(nil)
		entries, err := fetcher.FetchAuthorizedEntries(context.Background(), agentID)
		assert.NoError(t, err)
		assert.ElementsMatch(t, []*types.Entry{
			nodeAliasEntry,
			workload1Entry,
			workload2Entry,
		}, entries)
	})

	t.Run("failure", func(t *testing.T) {
		ds.SetNextError(errors.New("ohno"))
		entries, err := fetcher.FetchAuthorizedEntries(context.Background(), agentID)
		assert.EqualError(t, err, "ohno")
		assert.Nil(t, entries)
	})
}

func TestAgentAuthorizer(t *testing.T) {
	ca := testca.New(t, testTD)
	agentSVID := ca.CreateX509SVID(agentID).Certificates[0]

	for _, tt := range []struct {
		name           string
		failFetch      bool
		node           *common.AttestedNode
		time           time.Time
		expectedCode   codes.Code
		expectedMsg    string
		expectedReason types.PermissionDeniedDetails_Reason
		expectedLogs   []spiretest.LogEntry
	}{
		{
			name: "authorized",
			node: &common.AttestedNode{
				SpiffeId:         agentID.String(),
				CertSerialNumber: agentSVID.SerialNumber.String(),
			},
			expectedCode: codes.OK,
		},
		{
			name:         "fail fetch",
			failFetch:    true,
			expectedCode: codes.Internal,
			expectedMsg:  "unable to look up agent information",
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Unable to look up agent information",
					Data: map[string]interface{}{
						logrus.ErrorKey:   "ohno",
						telemetry.AgentID: agentID.String(),
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
			expectedMsg:    `agent "spiffe://domain.test/agent" SVID is expired`,
			expectedReason: types.PermissionDeniedDetails_AGENT_EXPIRED,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent SVID is expired",
					Data: map[string]interface{}{
						telemetry.AgentID: agentID.String(),
					},
				},
			},
		},
		{
			name:           "no attested node",
			expectedCode:   codes.PermissionDenied,
			expectedMsg:    `agent "spiffe://domain.test/agent" is not attested`,
			expectedReason: types.PermissionDeniedDetails_AGENT_NOT_ATTESTED,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent is not attested",
					Data: map[string]interface{}{
						telemetry.AgentID: agentID.String(),
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
			expectedMsg:    `agent "spiffe://domain.test/agent" is banned`,
			expectedReason: types.PermissionDeniedDetails_AGENT_BANNED,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent is banned",
					Data: map[string]interface{}{
						telemetry.AgentID: agentID.String(),
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
			expectedMsg:    fmt.Sprintf(`agent "spiffe://domain.test/agent" expected to have serial number "NEW"; has %q`, agentSVID.SerialNumber),
			expectedReason: types.PermissionDeniedDetails_AGENT_NOT_ACTIVE,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Agent SVID is not active",
					Data: map[string]interface{}{
						telemetry.AgentID:          agentID.String(),
						telemetry.SVIDSerialNumber: agentSVID.SerialNumber.String(),
						telemetry.SerialNumber:     "NEW",
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
				_, err := ds.CreateAttestedNode(context.Background(), &datastore.CreateAttestedNodeRequest{
					Node: tt.node,
				})
				require.NoError(t, err)
			}

			if tt.failFetch {
				ds.SetNextError(errors.New("ohno"))
			}

			clk := clock.NewMock(t)
			if !tt.time.IsZero() {
				clk.Set(tt.time)
			}
			authorizer := AgentAuthorizer(log, ds, clk)
			err := authorizer.AuthorizeAgent(context.Background(), agentID, agentSVID)
			spiretest.RequireGRPCStatus(t, err, tt.expectedCode, tt.expectedMsg)
			if tt.expectedCode == codes.PermissionDenied {
				// Assert that the expected permission denied reason is returned
				assert.Equal(t, []interface{}{
					&types.PermissionDeniedDetails{
						Reason: tt.expectedReason,
					},
				}, status.Convert(err).Details())
			}
			spiretest.AssertLogs(t, hook.AllEntries(), tt.expectedLogs)
		})
	}
}
