package entry_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/entry/v1"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/grpctest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	ctx               = context.Background()
	td                = spiffeid.RequireTrustDomainFromString("example.org")
	federatedTd       = spiffeid.RequireTrustDomainFromString("domain1.org")
	secondFederatedTd = spiffeid.RequireTrustDomainFromString("domain2.org")
	notFederatedTd    = spiffeid.RequireTrustDomainFromString("domain3.org")
	agentID           = spiffeid.RequireFromString("spiffe://example.org/agent")
)

func TestCountEntries(t *testing.T) {
	for _, tt := range []struct {
		name       string
		count      int32
		resp       *entryv1.CountEntriesResponse
		code       codes.Code
		dsError    error
		err        string
		expectLogs []spiretest.LogEntry
	}{
		{
			name:  "0 entries",
			count: 0,
			resp:  &entryv1.CountEntriesResponse{Count: 0},
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
			name:  "1 entries",
			count: 1,
			resp:  &entryv1.CountEntriesResponse{Count: 1},
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
			name:  "2 entries",
			count: 2,
			resp:  &entryv1.CountEntriesResponse{Count: 2},
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
			name:  "3 entries",
			count: 3,
			resp:  &entryv1.CountEntriesResponse{Count: 3},
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
			err:     "failed to count entries: ds error",
			code:    codes.Internal,
			dsError: status.Error(codes.Internal, "ds error"),
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to count entries",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = ds error",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to count entries: ds error",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ds := fakedatastore.New(t)
			test := setupServiceTest(t, ds)
			defer test.Cleanup()

			for i := range int(tt.count) {
				_, err := test.ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
					ParentId: spiffeid.RequireFromSegments(td, fmt.Sprintf("parent%d", i)).String(),
					SpiffeId: spiffeid.RequireFromSegments(td, fmt.Sprintf("child%d", i)).String(),
					Selectors: []*common.Selector{
						{Type: "unix", Value: "uid:1000"},
						{Type: "unix", Value: "gid:1000"},
					},
				})
				require.NoError(t, err)
			}

			ds.SetNextError(tt.dsError)
			resp, err := test.client.CountEntries(context.Background(), &entryv1.CountEntriesRequest{})

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			spiretest.AssertProtoEqual(t, tt.resp, resp)
			require.Equal(t, tt.count, resp.Count)
		})
	}
}

func TestListEntries(t *testing.T) {
	parentID := spiffeid.RequireFromSegments(td, "parent")
	childID := spiffeid.RequireFromSegments(td, "child")
	secondChildID := spiffeid.RequireFromSegments(td, "second_child")

	protoParentID := api.ProtoFromID(parentID)
	protoChildID := api.ProtoFromID(childID)
	protoSecondChildID := api.ProtoFromID(secondChildID)
	badID := &types.SPIFFEID{
		Path: "/bad",
	}

	childRegEntry := &common.RegistrationEntry{
		ParentId: parentID.String(),
		SpiffeId: childID.String(),
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
		FederatesWith: []string{
			federatedTd.IDString(),
		},
		Hint: "internal",
	}
	secondChildRegEntry := &common.RegistrationEntry{
		ParentId: parentID.String(),
		SpiffeId: secondChildID.String(),
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:1000"},
		},
		FederatesWith: []string{
			federatedTd.IDString(),
			secondFederatedTd.IDString(),
		},
		Hint: "external",
	}
	badRegEntry := &common.RegistrationEntry{
		ParentId: spiffeid.RequireFromSegments(td, "malformed").String(),
		SpiffeId: "zzz://malformed id",
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:1001"},
		},
	}

	// setup
	ds := fakedatastore.New(t)
	test := setupServiceTest(t, ds)
	defer test.Cleanup()

	// Create federated bundles, that we use on "FederatesWith"
	createFederatedBundles(t, test.ds)

	childEntry, err := test.ds.CreateRegistrationEntry(ctx, childRegEntry)
	require.NoError(t, err)
	require.NotNil(t, childEntry)

	secondChildEntry, err := test.ds.CreateRegistrationEntry(ctx, secondChildRegEntry)
	require.NoError(t, err)
	require.NotNil(t, secondChildEntry)

	badEntry, err := test.ds.CreateRegistrationEntry(ctx, badRegEntry)
	require.NoError(t, err)
	require.NotNil(t, badEntry)

	// expected entries
	expectedChild := &types.Entry{
		Id:       childEntry.EntryId,
		ParentId: protoParentID,
		SpiffeId: protoChildID,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "gid:1000"},
			{Type: "unix", Value: "uid:1000"},
		},
		FederatesWith: []string{
			federatedTd.Name(),
		},
		Hint:      "internal",
		CreatedAt: childEntry.CreatedAt,
	}

	expectedSecondChild := &types.Entry{
		Id:       secondChildEntry.EntryId,
		ParentId: protoParentID,
		SpiffeId: protoSecondChildID,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
		},
		FederatesWith: []string{
			federatedTd.Name(),
			secondFederatedTd.Name(),
		},
		Hint:      "external",
		CreatedAt: secondChildEntry.CreatedAt,
	}

	for _, tt := range []struct {
		name                  string
		err                   string
		code                  codes.Code
		expectLogs            []spiretest.LogEntry
		dsError               error
		expectedNextPageToken string
		expectedEntries       []*types.Entry
		request               *entryv1.ListEntriesRequest
	}{
		{
			name: "happy path",
			expectedEntries: []*types.Entry{
				{
					Id:       childEntry.EntryId,
					SpiffeId: protoChildID,
				},
			},
			request: &entryv1.ListEntriesRequest{
				OutputMask: &types.EntryMask{
					SpiffeId: true,
				},
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySpiffeId: protoChildID,
					ByParentId: protoParentID,
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "unix", Value: "uid:1000"},
							{Type: "unix", Value: "gid:1000"},
						},
						Match: types.SelectorMatch_MATCH_EXACT,
					},
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							federatedTd.IDString(),
						},
						Match: types.FederatesWithMatch_MATCH_EXACT,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.BySelectorMatch:    "MATCH_EXACT",
						telemetry.BySelectors:        "unix:uid:1000,unix:gid:1000",
						telemetry.FederatesWith:      "spiffe://domain1.org",
						telemetry.FederatesWithMatch: "MATCH_EXACT",
						telemetry.ParentID:           "spiffe://example.org/parent",
						telemetry.SPIFFEID:           "spiffe://example.org/child",
					},
				},
			},
		},
		{
			name:            "empty request",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request:         &entryv1.ListEntriesRequest{},
			expectLogs: []spiretest.LogEntry{
				// Error is expected when trying to parse a malformed RegistrationEntry into types.Entry,
				// but test case will not fail, just log it.
				{
					Level:   logrus.ErrorLevel,
					Message: fmt.Sprintf("Failed to convert entry: %q", badEntry.EntryId),
					Data: logrus.Fields{
						logrus.ErrorKey: `invalid SPIFFE ID: scheme is missing or invalid`,
					},
				},
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
			name:            "filter by parent ID",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByParentId: protoParentID,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.ParentID: "spiffe://example.org/parent",
					},
				},
			},
		},
		{
			name:            "filter by SPIFFE ID",
			expectedEntries: []*types.Entry{expectedChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySpiffeId: protoChildID,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:   "success",
						telemetry.Type:     "audit",
						telemetry.SPIFFEID: "spiffe://example.org/child",
					},
				},
			},
		},
		{
			name:            "filter by Hint",
			expectedEntries: []*types.Entry{expectedChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByHint: wrapperspb.String("internal"),
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "success",
						telemetry.Type:   "audit",
						telemetry.Hint:   "internal",
					},
				},
			},
		},
		{
			name:            "filter by selectors exact match",
			expectedEntries: []*types.Entry{expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "unix", Value: "uid:1000"},
						},
						Match: types.SelectorMatch_MATCH_EXACT,
					},
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
						telemetry.BySelectors:     "unix:uid:1000",
					},
				},
			},
		},
		{
			name:            "filter by selectors subset match",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "unix", Value: "uid:1000"},
							{Type: "unix", Value: "gid:1000"},
							{Type: "unix", Value: "user:me"},
						},
						Match: types.SelectorMatch_MATCH_SUBSET,
					},
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
						telemetry.BySelectors:     "unix:uid:1000,unix:gid:1000,unix:user:me",
					},
				},
			},
		},
		{
			name:            "filter by selectors match any",
			expectedEntries: []*types.Entry{expectedChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "unix", Value: "gid:1000"},
						},
						Match: types.SelectorMatch_MATCH_ANY,
					},
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
						telemetry.BySelectors:     "unix:gid:1000",
					},
				},
			},
		},
		{
			name:            "filter by selectors superset",
			expectedEntries: []*types.Entry{expectedChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "unix", Value: "gid:1000"},
							{Type: "unix", Value: "uid:1000"},
						},
						Match: types.SelectorMatch_MATCH_SUPERSET,
					},
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
						telemetry.BySelectors:     "unix:gid:1000,unix:uid:1000",
					},
				},
			},
		},
		{
			name:            "filter by federates with exact match (no subset)",
			expectedEntries: []*types.Entry{expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.Name(),
						},
						Match: types.FederatesWithMatch_MATCH_EXACT,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_EXACT",
						telemetry.FederatesWith:      "spiffe://domain1.org,domain2.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with exact match (no superset)",
			expectedEntries: []*types.Entry{expectedChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							federatedTd.IDString(),
						},
						Match: types.FederatesWithMatch_MATCH_EXACT,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_EXACT",
						telemetry.FederatesWith:      "spiffe://domain1.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with exact match (with repeated tds)",
			expectedEntries: []*types.Entry{expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.IDString(),
							secondFederatedTd.Name(), // repeated td
						},
						Match: types.FederatesWithMatch_MATCH_EXACT,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_EXACT",
						telemetry.FederatesWith:      "spiffe://domain1.org,spiffe://domain2.org,domain2.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with exact match (not federated)",
			expectedEntries: []*types.Entry{},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							notFederatedTd.Name(),
						},
						Match: types.FederatesWithMatch_MATCH_EXACT,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_EXACT",
						telemetry.FederatesWith:      "domain3.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with subset match",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.Name(),
							notFederatedTd.IDString(),
						},
						Match: types.FederatesWithMatch_MATCH_SUBSET,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_SUBSET",
						telemetry.FederatesWith:      "spiffe://domain1.org,domain2.org,spiffe://domain3.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with subset match (no superset)",
			expectedEntries: []*types.Entry{expectedChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							federatedTd.IDString(),
						},
						Match: types.FederatesWithMatch_MATCH_SUBSET,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_SUBSET",
						telemetry.FederatesWith:      "spiffe://domain1.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with subset match (with repeated tds)",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.IDString(),
							secondFederatedTd.Name(), // repeated td
						},
						Match: types.FederatesWithMatch_MATCH_SUBSET,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_SUBSET",
						telemetry.FederatesWith:      "spiffe://domain1.org,spiffe://domain2.org,domain2.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with subset match (not federated)",
			expectedEntries: []*types.Entry{},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							notFederatedTd.Name(),
						},
						Match: types.FederatesWithMatch_MATCH_SUBSET,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_SUBSET",
						telemetry.FederatesWith:      "domain3.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with match any (no subset)",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.Name(),
						},
						Match: types.FederatesWithMatch_MATCH_ANY,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_ANY",
						telemetry.FederatesWith:      "spiffe://domain1.org,domain2.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with match any (no superset)",
			expectedEntries: []*types.Entry{expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							secondFederatedTd.IDString(),
						},
						Match: types.FederatesWithMatch_MATCH_ANY,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_ANY",
						telemetry.FederatesWith:      "spiffe://domain2.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with match any (with repeated tds)",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.IDString(),
							secondFederatedTd.Name(), // repeated td
						},
						Match: types.FederatesWithMatch_MATCH_ANY,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_ANY",
						telemetry.FederatesWith:      "spiffe://domain1.org,spiffe://domain2.org,domain2.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with match any (not federated)",
			expectedEntries: []*types.Entry{},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							notFederatedTd.Name(),
						},
						Match: types.FederatesWithMatch_MATCH_ANY,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_ANY",
						telemetry.FederatesWith:      "domain3.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with superset match",
			expectedEntries: []*types.Entry{expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.Name(),
						},
						Match: types.FederatesWithMatch_MATCH_SUPERSET,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_SUPERSET",
						telemetry.FederatesWith:      "spiffe://domain1.org,domain2.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with subset match (superset)",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							federatedTd.IDString(),
						},
						Match: types.FederatesWithMatch_MATCH_SUPERSET,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_SUPERSET",
						telemetry.FederatesWith:      "spiffe://domain1.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with subset match (with repeated tds)",
			expectedEntries: []*types.Entry{expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.IDString(),
							secondFederatedTd.Name(), // repeated td
						},
						Match: types.FederatesWithMatch_MATCH_SUPERSET,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_SUPERSET",
						telemetry.FederatesWith:      "spiffe://domain1.org,spiffe://domain2.org,domain2.org",
					},
				},
			},
		},
		{
			name:            "filter by federates with subset match (no match)",
			expectedEntries: []*types.Entry{},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							notFederatedTd.IDString(),
						},
						Match: types.FederatesWithMatch_MATCH_SUPERSET,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "success",
						telemetry.Type:               "audit",
						telemetry.FederatesWithMatch: "MATCH_SUPERSET",
						telemetry.FederatesWith:      "spiffe://domain3.org",
					},
				},
			},
		},
		{
			name:                  "page",
			expectedEntries:       []*types.Entry{expectedChild},
			expectedNextPageToken: "1",
			request: &entryv1.ListEntriesRequest{
				PageSize: 1,
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
			name:    "ds error",
			err:     "failed to list entries: ds error",
			code:    codes.Internal,
			dsError: errors.New("ds error"),
			request: &entryv1.ListEntriesRequest{},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to list entries",
					Data: logrus.Fields{
						logrus.ErrorKey: "ds error",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to list entries: ds error",
					},
				},
			},
		},
		{
			name: "bad parent ID filter",
			err:  "malformed parent ID filter: trust domain is missing",
			code: codes.InvalidArgument,
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByParentId: badID,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: malformed parent ID filter",
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
						telemetry.StatusMessage: "malformed parent ID filter: trust domain is missing",
					},
				},
			},
		},
		{
			name: "bad SPIFFE ID filter",
			err:  "malformed SPIFFE ID filter: trust domain is missing",
			code: codes.InvalidArgument,
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySpiffeId: badID,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: malformed SPIFFE ID filter",
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
						telemetry.StatusMessage: "malformed SPIFFE ID filter: trust domain is missing",
					},
				},
			},
		},
		{
			name:            "bad selectors filter (no selectors)",
			err:             "malformed selectors filter: empty selector set",
			code:            codes.InvalidArgument,
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: malformed selectors filter",
					Data: logrus.Fields{
						logrus.ErrorKey: "empty selector set",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:          "error",
						telemetry.Type:            "audit",
						telemetry.StatusCode:      "InvalidArgument",
						telemetry.StatusMessage:   "malformed selectors filter: empty selector set",
						telemetry.BySelectorMatch: "MATCH_EXACT",
						telemetry.BySelectors:     "",
					},
				},
			},
		},
		{
			name: "bad selectors filter (bad selector)",
			err:  "malformed selectors filter: missing selector type",
			code: codes.InvalidArgument,
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "", Value: "uid:1000"},
						},
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: malformed selectors filter",
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
						telemetry.StatusMessage:   "malformed selectors filter: missing selector type",
						telemetry.BySelectorMatch: "MATCH_EXACT",
						telemetry.BySelectors:     ":uid:1000",
					},
				},
			},
		},
		{
			name: "bad federates with filter (no trust domains)",
			err:  "malformed federates with filter: empty trust domain set",
			code: codes.InvalidArgument,
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: malformed federates with filter",
					Data: logrus.Fields{
						logrus.ErrorKey: "empty trust domain set",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "error",
						telemetry.Type:               "audit",
						telemetry.StatusCode:         "InvalidArgument",
						telemetry.StatusMessage:      "malformed federates with filter: empty trust domain set",
						telemetry.FederatesWith:      "",
						telemetry.FederatesWithMatch: "MATCH_EXACT",
					},
				},
			},
		},
		{
			name: "bad federates with filter (bad trust domain)",
			err:  "malformed federates with filter: trust domain is missing",
			code: codes.InvalidArgument,
			request: &entryv1.ListEntriesRequest{
				Filter: &entryv1.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							badID.TrustDomain,
						},
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: malformed federates with filter",
					Data: logrus.Fields{
						logrus.ErrorKey: "trust domain is missing",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:             "error",
						telemetry.Type:               "audit",
						telemetry.StatusCode:         "InvalidArgument",
						telemetry.StatusMessage:      "malformed federates with filter: trust domain is missing",
						telemetry.FederatesWith:      "",
						telemetry.FederatesWithMatch: "MATCH_EXACT",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()
			ds.SetNextError(tt.dsError)

			// exercise
			entries, err := test.client.ListEntries(context.Background(), tt.request)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)

			if tt.err != "" {
				require.Nil(t, entries)
				require.Error(t, err)
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, entries)
			spiretest.AssertProtoListEqual(t, tt.expectedEntries, entries.Entries)
			assert.Equal(t, tt.expectedNextPageToken, entries.NextPageToken)
		})
	}
}

func TestGetEntry(t *testing.T) {
	now := time.Now().Unix()
	ds := fakedatastore.New(t)
	test := setupServiceTest(t, ds)
	defer test.Cleanup()

	// Create federated bundles, that we use on "FederatesWith"
	createFederatedBundles(t, test.ds)

	parent := spiffeid.RequireFromSegments(td, "foo")
	entry1SpiffeID := spiffeid.RequireFromSegments(td, "bar")
	expiresAt := time.Now().Unix()
	goodEntry, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		ParentId:    parent.String(),
		SpiffeId:    entry1SpiffeID.String(),
		X509SvidTtl: 60,
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
		FederatesWith: []string{
			federatedTd.IDString(),
		},
		Admin:       true,
		EntryExpiry: expiresAt,
		DnsNames:    []string{"dns1", "dns2"},
		Downstream:  true,
		Hint:        "internal",
	})
	require.NoError(t, err)

	malformedEntry, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		ParentId: parent.String(),
		SpiffeId: "malformed id",
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:1000"},
		},
		EntryExpiry: expiresAt,
	})
	require.NoError(t, err)

	for _, tt := range []struct {
		name        string
		code        codes.Code
		dsError     error
		entryID     string
		err         string
		expectEntry *types.Entry
		expectLogs  []spiretest.LogEntry
		outputMask  *types.EntryMask
	}{
		{
			name:    "success",
			entryID: goodEntry.EntryId,
			expectEntry: &types.Entry{
				Id:       goodEntry.EntryId,
				ParentId: api.ProtoFromID(parent),
				SpiffeId: api.ProtoFromID(entry1SpiffeID),
			},
			outputMask: &types.EntryMask{
				ParentId: true,
				SpiffeId: true,
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.RegistrationID: goodEntry.EntryId,
					},
				},
			},
		},
		{
			name:    "no outputMask",
			entryID: goodEntry.EntryId,
			expectEntry: &types.Entry{
				Id:          goodEntry.EntryId,
				ParentId:    api.ProtoFromID(parent),
				SpiffeId:    api.ProtoFromID(entry1SpiffeID),
				X509SvidTtl: 60,
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{federatedTd.Name()},
				Admin:         true,
				DnsNames:      []string{"dns1", "dns2"},
				Downstream:    true,
				ExpiresAt:     expiresAt,
				Hint:          "internal",
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.RegistrationID: goodEntry.EntryId,
					},
				},
			},
		},
		{
			name:        "outputMask all false",
			entryID:     goodEntry.EntryId,
			expectEntry: &types.Entry{Id: goodEntry.EntryId},
			outputMask:  &types.EntryMask{},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.RegistrationID: goodEntry.EntryId,
					},
				},
			},
		},
		{
			name: "missing ID",
			code: codes.InvalidArgument,
			err:  "missing ID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: missing ID",
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "missing ID",
					},
				},
			},
		},
		{
			name:    "fetch fails",
			code:    codes.Internal,
			entryID: goodEntry.EntryId,
			err:     "failed to fetch entry: ds error",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch entry",
					Data: logrus.Fields{
						telemetry.RegistrationID: goodEntry.EntryId,
						logrus.ErrorKey:          "ds error",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.RegistrationID: goodEntry.EntryId,
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.StatusCode:     "Internal",
						telemetry.StatusMessage:  "failed to fetch entry: ds error",
					},
				},
			},
			dsError: errors.New("ds error"),
		},
		{
			name:    "entry not found",
			code:    codes.NotFound,
			entryID: "invalidEntryID",
			err:     "entry not found",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Entry not found",
					Data: logrus.Fields{
						telemetry.RegistrationID: "invalidEntryID",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.StatusCode:     "NotFound",
						telemetry.StatusMessage:  "entry not found",
						telemetry.RegistrationID: "invalidEntryID",
					},
				},
			},
		},
		{
			name:    "malformed entry",
			code:    codes.Internal,
			entryID: malformedEntry.EntryId,
			err:     "failed to convert entry: invalid SPIFFE ID: scheme is missing or invalid",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to convert entry",
					Data: logrus.Fields{
						telemetry.RegistrationID: malformedEntry.EntryId,
						logrus.ErrorKey:          "invalid SPIFFE ID: scheme is missing or invalid",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.StatusCode:     "Internal",
						telemetry.StatusMessage:  "failed to convert entry: invalid SPIFFE ID: scheme is missing or invalid",
						telemetry.RegistrationID: malformedEntry.EntryId,
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()
			ds.SetNextError(tt.dsError)

			resp, err := test.client.GetEntry(ctx, &entryv1.GetEntryRequest{
				Id:         tt.entryID,
				OutputMask: tt.outputMask,
			})

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			if tt.outputMask == nil || tt.outputMask.CreatedAt {
				assert.GreaterOrEqual(t, resp.CreatedAt, now)
				resp.CreatedAt = tt.expectEntry.CreatedAt
			}
			spiretest.AssertProtoEqual(t, tt.expectEntry, resp)
		})
	}
}

func TestBatchCreateEntry(t *testing.T) {
	entryParentID := spiffeid.RequireFromSegments(td, "foo")
	entrySpiffeID := spiffeid.RequireFromSegments(td, "bar")
	expiresAt := time.Now().Unix()

	useDefaultEntryID := "DEFAULT_ENTRY_ID"

	defaultEntry := &common.RegistrationEntry{
		ParentId:    entryParentID.String(),
		SpiffeId:    entrySpiffeID.String(),
		X509SvidTtl: 60,
		Selectors: []*common.Selector{
			{Type: "unix", Value: "gid:1000"},
			{Type: "unix", Value: "uid:1000"},
		},
		Admin:         true,
		DnsNames:      []string{"dns1", "dns2"},
		Downstream:    true,
		EntryExpiry:   expiresAt,
		FederatesWith: []string{federatedTd.IDString()},
	}

	// Create a test entry
	testEntry := &types.Entry{
		Id:       "entry1",
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
		Selectors: []*types.Selector{
			{Type: "type", Value: "value1"},
			{Type: "type", Value: "value2"},
		},
		Admin:         true,
		DnsNames:      []string{"dns1"},
		Downstream:    true,
		ExpiresAt:     expiresAt,
		FederatesWith: []string{"domain1.org"},
		X509SvidTtl:   45,
		JwtSvidTtl:    30,
		Hint:          "external",
	}
	// Registration entry for test entry
	testDSEntry := &common.RegistrationEntry{
		EntryId:  "entry1",
		ParentId: "spiffe://example.org/host",
		SpiffeId: "spiffe://example.org/workload",
		Selectors: []*common.Selector{
			{Type: "type", Value: "value1"},
			{Type: "type", Value: "value2"},
		},
		Admin:         true,
		DnsNames:      []string{"dns1"},
		Downstream:    true,
		EntryExpiry:   expiresAt,
		FederatesWith: []string{"spiffe://domain1.org"},
		X509SvidTtl:   45,
		JwtSvidTtl:    30,
		Hint:          "external",
		CreatedAt:     1678731397,
	}

	for _, tt := range []struct {
		name          string
		expectLogs    []spiretest.LogEntry
		expectResults []*entryv1.BatchCreateEntryResponse_Result
		expectStatus  *types.Status
		outputMask    *types.EntryMask
		reqEntries    []*types.Entry

		// fake ds configurations
		noCustomCreate  bool
		dsError         error
		dsResults       map[string]*common.RegistrationEntry
		expectDsEntries map[string]*common.RegistrationEntry
	}{
		{
			name: "multiple entries",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.Admin:          "true",
						telemetry.DNSName:        "dns1",
						telemetry.Downstream:     "true",
						telemetry.RegistrationID: "entry1",
						telemetry.ExpiresAt:      strconv.FormatInt(testEntry.ExpiresAt, 10),
						telemetry.FederatesWith:  "domain1.org",
						telemetry.ParentID:       "spiffe://example.org/host",
						telemetry.Selectors:      "type:value1,type:value2",
						telemetry.RevisionNumber: "0",
						telemetry.SPIFFEID:       "spiffe://example.org/workload",
						telemetry.X509SVIDTTL:    "45",
						telemetry.JWTSVIDTTL:     "30",
						telemetry.StoreSvid:      "false",
						telemetry.Hint:           "external",
						telemetry.CreatedAt:      "0",
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert entry",
					Data: logrus.Fields{
						logrus.ErrorKey: "invalid DNS name: empty or only whitespace",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.StatusCode:     "InvalidArgument",
						telemetry.StatusMessage:  "failed to convert entry: invalid DNS name: empty or only whitespace",
						telemetry.Admin:          "false",
						telemetry.Downstream:     "false",
						telemetry.ExpiresAt:      "0",
						telemetry.ParentID:       "spiffe://example.org/agent",
						telemetry.RevisionNumber: "0",
						telemetry.Selectors:      "type:value",
						telemetry.SPIFFEID:       "spiffe://example.org/malformed",
						telemetry.X509SVIDTTL:    "0",
						telemetry.JWTSVIDTTL:     "0",
						telemetry.StoreSvid:      "false",
						telemetry.Hint:           "",
						telemetry.CreatedAt:      "0",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.Admin:          "false",
						telemetry.Downstream:     "false",
						telemetry.RegistrationID: "entry2",
						telemetry.ExpiresAt:      "0",
						telemetry.ParentID:       "spiffe://example.org/agent",
						telemetry.RevisionNumber: "0",
						telemetry.Selectors:      "type:value",
						telemetry.SPIFFEID:       "spiffe://example.org/workload2",
						telemetry.X509SVIDTTL:    "0",
						telemetry.JWTSVIDTTL:     "0",
						telemetry.StoreSvid:      "false",
						telemetry.Hint:           "",
						telemetry.CreatedAt:      "0",
					},
				},
			},
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Id:       "entry1",
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					},
				},
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to convert entry: invalid DNS name: empty or only whitespace",
					},
				},
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Id:       "entry2",
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload2"},
					},
				},
			},
			outputMask: &types.EntryMask{
				ParentId: true,
				SpiffeId: true,
			},
			reqEntries: []*types.Entry{
				testEntry,
				{
					ParentId: &types.SPIFFEID{
						TrustDomain: "example.org",
						Path:        "/agent",
					},
					SpiffeId: &types.SPIFFEID{
						TrustDomain: "example.org",
						Path:        "/malformed",
					},
					Selectors: []*types.Selector{{Type: "type", Value: "value"}},
					DnsNames:  []string{""},
				},
				{
					Id: "entry2",
					ParentId: &types.SPIFFEID{
						TrustDomain: "example.org",
						Path:        "/agent",
					},
					SpiffeId: &types.SPIFFEID{
						TrustDomain: "example.org",
						Path:        "/workload2",
					},
					Selectors: []*types.Selector{{Type: "type", Value: "value"}},
				},
			},
			expectDsEntries: map[string]*common.RegistrationEntry{
				"entry1": testDSEntry,
				"entry2": {EntryId: "entry2", ParentId: "spiffe://example.org/agent", SpiffeId: "spiffe://example.org/workload2", Selectors: []*common.Selector{{Type: "type", Value: "value"}}},
			},
		},
		{
			name: "valid entry with hint",
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Id:       "entry1",
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/svidstore"},
						Hint:     "internal",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.Admin:          "false",
						telemetry.Downstream:     "false",
						telemetry.RegistrationID: "entry1",
						telemetry.ExpiresAt:      "0",
						telemetry.ParentID:       "spiffe://example.org/agent",
						telemetry.Selectors:      "type:value1,type:value2",
						telemetry.RevisionNumber: "0",
						telemetry.SPIFFEID:       "spiffe://example.org/svidstore",
						telemetry.X509SVIDTTL:    "0",
						telemetry.JWTSVIDTTL:     "0",
						telemetry.StoreSvid:      "false",
						telemetry.Hint:           "internal",
						telemetry.CreatedAt:      "0",
					},
				},
			},
			outputMask: &types.EntryMask{
				ParentId: true,
				SpiffeId: true,
				Hint:     true,
			},
			reqEntries: []*types.Entry{
				{
					Id: "entry1",
					ParentId: &types.SPIFFEID{
						TrustDomain: "example.org",
						Path:        "/agent",
					},
					SpiffeId: &types.SPIFFEID{
						TrustDomain: "example.org",
						Path:        "/svidstore",
					},
					Selectors: []*types.Selector{
						{Type: "type", Value: "value1"},
						{Type: "type", Value: "value2"},
					},
					Hint: "internal",
				},
			},
			expectDsEntries: map[string]*common.RegistrationEntry{
				"entry1": {
					EntryId:  "entry1",
					ParentId: "spiffe://example.org/agent",
					SpiffeId: "spiffe://example.org/svidstore",
					Selectors: []*common.Selector{
						{Type: "type", Value: "value1"},
						{Type: "type", Value: "value2"},
					},
					Hint: "internal",
				},
			},
		},
		{
			name: "valid store SVID entry",
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Id:        "entry1",
						ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
						SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/svidstore"},
						StoreSvid: true,
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.Admin:          "false",
						telemetry.Downstream:     "false",
						telemetry.RegistrationID: "entry1",
						telemetry.ExpiresAt:      "0",
						telemetry.ParentID:       "spiffe://example.org/agent",
						telemetry.Selectors:      "type:value1,type:value2",
						telemetry.RevisionNumber: "0",
						telemetry.SPIFFEID:       "spiffe://example.org/svidstore",
						telemetry.X509SVIDTTL:    "0",
						telemetry.JWTSVIDTTL:     "0",
						telemetry.StoreSvid:      "true",
						telemetry.Hint:           "",
						telemetry.CreatedAt:      "0",
					},
				},
			},
			outputMask: &types.EntryMask{
				ParentId:  true,
				SpiffeId:  true,
				StoreSvid: true,
			},
			reqEntries: []*types.Entry{
				{
					Id: "entry1",
					ParentId: &types.SPIFFEID{
						TrustDomain: "example.org",
						Path:        "/agent",
					},
					SpiffeId: &types.SPIFFEID{
						TrustDomain: "example.org",
						Path:        "/svidstore",
					},
					Selectors: []*types.Selector{
						{Type: "type", Value: "value1"},
						{Type: "type", Value: "value2"},
					},
					StoreSvid: true,
				},
			},
			expectDsEntries: map[string]*common.RegistrationEntry{
				"entry1": {
					EntryId:  "entry1",
					ParentId: "spiffe://example.org/agent",
					SpiffeId: "spiffe://example.org/svidstore",
					Selectors: []*common.Selector{
						{Type: "type", Value: "value1"},
						{Type: "type", Value: "value2"},
					},
					StoreSvid: true,
				},
			},
		},
		{
			name: "no output mask",
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Id:       "entry1",
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
						Selectors: []*types.Selector{
							{Type: "type", Value: "value1"},
							{Type: "type", Value: "value2"},
						},
						Admin:         true,
						DnsNames:      []string{"dns1"},
						Downstream:    true,
						ExpiresAt:     expiresAt,
						FederatesWith: []string{"domain1.org"},
						X509SvidTtl:   45,
						JwtSvidTtl:    30,
						StoreSvid:     false,
						Hint:          "external",
						CreatedAt:     1678731397,
					},
				},
			},
			reqEntries:      []*types.Entry{testEntry},
			expectDsEntries: map[string]*common.RegistrationEntry{"entry1": testDSEntry},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.Admin:          "true",
						telemetry.DNSName:        "dns1",
						telemetry.Downstream:     "true",
						telemetry.RegistrationID: "entry1",
						telemetry.ExpiresAt:      strconv.FormatInt(testEntry.ExpiresAt, 10),
						telemetry.FederatesWith:  "domain1.org",
						telemetry.ParentID:       "spiffe://example.org/host",
						telemetry.RevisionNumber: "0",
						telemetry.Selectors:      "type:value1,type:value2",
						telemetry.SPIFFEID:       "spiffe://example.org/workload",
						telemetry.X509SVIDTTL:    "45",
						telemetry.JWTSVIDTTL:     "30",
						telemetry.StoreSvid:      "false",
						telemetry.Hint:           "external",
						telemetry.CreatedAt:      "0",
					},
				},
			},
		},
		{
			name: "output mask all false",
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Id: "entry1",
					},
				},
			},
			outputMask:      &types.EntryMask{},
			reqEntries:      []*types.Entry{testEntry},
			expectDsEntries: map[string]*common.RegistrationEntry{"entry1": testDSEntry},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.Admin:          "true",
						telemetry.DNSName:        "dns1",
						telemetry.Downstream:     "true",
						telemetry.RegistrationID: "entry1",
						telemetry.ExpiresAt:      strconv.FormatInt(testEntry.ExpiresAt, 10),
						telemetry.FederatesWith:  "domain1.org",
						telemetry.ParentID:       "spiffe://example.org/host",
						telemetry.RevisionNumber: "0",
						telemetry.Selectors:      "type:value1,type:value2",
						telemetry.SPIFFEID:       "spiffe://example.org/workload",
						telemetry.X509SVIDTTL:    "45",
						telemetry.JWTSVIDTTL:     "30",
						telemetry.StoreSvid:      "false",
						telemetry.Hint:           "external",
						telemetry.CreatedAt:      "0",
					},
				},
			},
		},
		{
			name:          "no entries to add",
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{},
			reqEntries:    []*types.Entry{},
		},
		{
			name: "create with same parent ID and spiffe ID but different selectors",
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Id:       "entry1",
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
					},
				},
			},
			outputMask: &types.EntryMask{
				ParentId: true,
				SpiffeId: true,
			},
			reqEntries: []*types.Entry{
				{
					Id:          "entry1",
					ParentId:    api.ProtoFromID(entryParentID),
					SpiffeId:    api.ProtoFromID(entrySpiffeID),
					X509SvidTtl: 45,
					JwtSvidTtl:  30,
					Selectors: []*types.Selector{
						{Type: "type", Value: "value1"},
					},
				},
			},
			expectDsEntries: map[string]*common.RegistrationEntry{
				"entry1": {
					EntryId:     "entry1",
					ParentId:    "spiffe://example.org/foo",
					SpiffeId:    "spiffe://example.org/bar",
					X509SvidTtl: 45,
					JwtSvidTtl:  30,
					Selectors: []*common.Selector{
						{Type: "type", Value: "value1"},
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.Admin:          "false",
						telemetry.Downstream:     "false",
						telemetry.RegistrationID: "entry1",
						telemetry.ExpiresAt:      "0",
						telemetry.ParentID:       "spiffe://example.org/foo",
						telemetry.RevisionNumber: "0",
						telemetry.Selectors:      "type:value1",
						telemetry.SPIFFEID:       "spiffe://example.org/bar",
						telemetry.X509SVIDTTL:    "45",
						telemetry.JWTSVIDTTL:     "30",
						telemetry.StoreSvid:      "false",
						telemetry.Hint:           "",
						telemetry.CreatedAt:      "0",
					},
				},
			},
		},
		{
			name: "create with custom entry ID",
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Id:       "entry1",
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					},
				},
			},
			outputMask: &types.EntryMask{
				ParentId: true,
				SpiffeId: true,
			},
			reqEntries:      []*types.Entry{testEntry},
			expectDsEntries: map[string]*common.RegistrationEntry{"entry1": testDSEntry},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "success",
						telemetry.Type:           "audit",
						telemetry.Admin:          "true",
						telemetry.DNSName:        "dns1",
						telemetry.Downstream:     "true",
						telemetry.RegistrationID: "entry1",
						telemetry.ExpiresAt:      strconv.FormatInt(testEntry.ExpiresAt, 10),
						telemetry.FederatesWith:  "domain1.org",
						telemetry.ParentID:       "spiffe://example.org/host",
						telemetry.RevisionNumber: "0",
						telemetry.Selectors:      "type:value1,type:value2",
						telemetry.SPIFFEID:       "spiffe://example.org/workload",
						telemetry.X509SVIDTTL:    "45",
						telemetry.JWTSVIDTTL:     "30",
						telemetry.StoreSvid:      "false",
						telemetry.Hint:           "external",
						telemetry.CreatedAt:      "0",
					},
				},
			},
			noCustomCreate: true,
		},
		{
			name: "returns existing similar entry",
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.AlreadyExists),
						Message: "similar entry already exists",
					},
					Entry: &types.Entry{
						Id:       useDefaultEntryID,
						ParentId: api.ProtoFromID(entryParentID),
						SpiffeId: api.ProtoFromID(entrySpiffeID),
					},
				},
				{
					Status: &types.Status{
						Code:    int32(codes.AlreadyExists),
						Message: "similar entry already exists",
					},
					Entry: &types.Entry{
						Id:       useDefaultEntryID,
						ParentId: api.ProtoFromID(entryParentID),
						SpiffeId: api.ProtoFromID(entrySpiffeID),
					},
				},
			},
			outputMask: &types.EntryMask{
				ParentId: true,
				SpiffeId: true,
			},
			reqEntries: []*types.Entry{
				{
					ParentId:    api.ProtoFromID(entryParentID),
					SpiffeId:    api.ProtoFromID(entrySpiffeID),
					X509SvidTtl: 45,
					JwtSvidTtl:  30,
					Admin:       false,
					Selectors: []*types.Selector{
						{Type: "unix", Value: "gid:1000"},
						{Type: "unix", Value: "uid:1000"},
					},
				},
				{
					// similar entry but with custom entry ID
					Id:          "some_other_ID",
					ParentId:    api.ProtoFromID(entryParentID),
					SpiffeId:    api.ProtoFromID(entrySpiffeID),
					X509SvidTtl: 45,
					JwtSvidTtl:  30,
					Admin:       false,
					Selectors: []*types.Selector{
						{Type: "unix", Value: "gid:1000"},
						{Type: "unix", Value: "uid:1000"},
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.Admin:          "false",
						telemetry.Downstream:     "false",
						telemetry.ExpiresAt:      "0",
						telemetry.ParentID:       "spiffe://example.org/foo",
						telemetry.Selectors:      "unix:gid:1000,unix:uid:1000",
						telemetry.RevisionNumber: "0",
						telemetry.SPIFFEID:       "spiffe://example.org/bar",
						telemetry.X509SVIDTTL:    "45",
						telemetry.JWTSVIDTTL:     "30",
						telemetry.StatusCode:     "AlreadyExists",
						telemetry.StatusMessage:  "similar entry already exists",
						telemetry.StoreSvid:      "false",
						telemetry.Hint:           "",
						telemetry.CreatedAt:      "0",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.Admin:          "false",
						telemetry.Downstream:     "false",
						telemetry.RegistrationID: "some_other_ID",
						telemetry.ExpiresAt:      "0",
						telemetry.ParentID:       "spiffe://example.org/foo",
						telemetry.Selectors:      "unix:gid:1000,unix:uid:1000",
						telemetry.RevisionNumber: "0",
						telemetry.SPIFFEID:       "spiffe://example.org/bar",
						telemetry.X509SVIDTTL:    "45",
						telemetry.JWTSVIDTTL:     "30",
						telemetry.StatusCode:     "AlreadyExists",
						telemetry.StatusMessage:  "similar entry already exists",
						telemetry.StoreSvid:      "false",
						telemetry.Hint:           "",
						telemetry.CreatedAt:      "0",
					},
				},
			},
			noCustomCreate: true,
		},
		{
			name: "invalid entry",
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to convert entry: invalid parent ID: trust domain is missing",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert entry",
					Data: logrus.Fields{
						logrus.ErrorKey: "invalid parent ID: trust domain is missing",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.Admin:          "false",
						telemetry.Downstream:     "false",
						telemetry.ExpiresAt:      "0",
						telemetry.RevisionNumber: "0",
						telemetry.X509SVIDTTL:    "0",
						telemetry.JWTSVIDTTL:     "0",
						telemetry.StoreSvid:      "false",
						telemetry.StatusCode:     "InvalidArgument",
						telemetry.StatusMessage:  "failed to convert entry: invalid parent ID: trust domain is missing",
						telemetry.Hint:           "",
						telemetry.CreatedAt:      "0",
					},
				},
			},
			reqEntries: []*types.Entry{
				{
					ParentId: &types.SPIFFEID{TrustDomain: "", Path: "/path"},
				},
			},
		},
		{
			name: "invalid entry ID",
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to create entry: datastore-validation: invalid registration entry: entry ID contains invalid characters",
					},
				},
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to create entry: datastore-validation: invalid registration entry: entry ID too long",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to create entry",
					Data: logrus.Fields{
						logrus.ErrorKey:    "rpc error: code = InvalidArgument desc = datastore-validation: invalid registration entry: entry ID contains invalid characters",
						telemetry.SPIFFEID: "spiffe://example.org/bar",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.Admin:          "false",
						telemetry.Downstream:     "false",
						telemetry.RegistrationID: "🙈🙉🙊",
						telemetry.ExpiresAt:      "0",
						telemetry.ParentID:       "spiffe://example.org/foo",
						telemetry.RevisionNumber: "0",
						telemetry.Selectors:      "type:value1",
						telemetry.SPIFFEID:       "spiffe://example.org/bar",
						telemetry.X509SVIDTTL:    "45",
						telemetry.JWTSVIDTTL:     "30",
						telemetry.Hint:           "",
						telemetry.CreatedAt:      "0",
						telemetry.StoreSvid:      "false",
						telemetry.StatusCode:     "InvalidArgument",
						telemetry.StatusMessage:  "failed to create entry: datastore-validation: invalid registration entry: entry ID contains invalid characters",
					},
				},
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to create entry",
					Data: logrus.Fields{
						logrus.ErrorKey:    "rpc error: code = InvalidArgument desc = datastore-validation: invalid registration entry: entry ID too long",
						telemetry.SPIFFEID: "spiffe://example.org/bar",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.Admin:          "false",
						telemetry.Downstream:     "false",
						telemetry.RegistrationID: strings.Repeat("y", 256),
						telemetry.ExpiresAt:      "0",
						telemetry.ParentID:       "spiffe://example.org/foo",
						telemetry.RevisionNumber: "0",
						telemetry.Selectors:      "type:value1",
						telemetry.SPIFFEID:       "spiffe://example.org/bar",
						telemetry.X509SVIDTTL:    "45",
						telemetry.JWTSVIDTTL:     "30",
						telemetry.Hint:           "",
						telemetry.CreatedAt:      "0",
						telemetry.StoreSvid:      "false",
						telemetry.StatusCode:     "InvalidArgument",
						telemetry.StatusMessage:  "failed to create entry: datastore-validation: invalid registration entry: entry ID too long",
					},
				},
			},
			reqEntries: []*types.Entry{
				{
					Id:          "🙈🙉🙊",
					ParentId:    api.ProtoFromID(entryParentID),
					SpiffeId:    api.ProtoFromID(entrySpiffeID),
					X509SvidTtl: 45,
					JwtSvidTtl:  30,
					Selectors: []*types.Selector{
						{Type: "type", Value: "value1"},
					},
				},
				{
					Id:          strings.Repeat("y", 256),
					ParentId:    api.ProtoFromID(entryParentID),
					SpiffeId:    api.ProtoFromID(entrySpiffeID),
					X509SvidTtl: 45,
					JwtSvidTtl:  30,
					Selectors: []*types.Selector{
						{Type: "type", Value: "value1"},
					},
				},
			},
			noCustomCreate: true,
		},
		{
			name: "fail creating entry",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to create entry",
					Data: logrus.Fields{
						logrus.ErrorKey:    "creating error",
						telemetry.SPIFFEID: "spiffe://example.org/workload",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:         "error",
						telemetry.Type:           "audit",
						telemetry.Admin:          "true",
						telemetry.DNSName:        "dns1",
						telemetry.Downstream:     "true",
						telemetry.RegistrationID: "entry1",
						telemetry.ExpiresAt:      strconv.FormatInt(testEntry.ExpiresAt, 10),
						telemetry.FederatesWith:  "domain1.org",
						telemetry.ParentID:       "spiffe://example.org/host",
						telemetry.RevisionNumber: "0",
						telemetry.Selectors:      "type:value1,type:value2",
						telemetry.SPIFFEID:       "spiffe://example.org/workload",
						telemetry.X509SVIDTTL:    "45",
						telemetry.JWTSVIDTTL:     "30",
						telemetry.Hint:           "external",
						telemetry.CreatedAt:      "0",
						telemetry.StoreSvid:      "false",
						telemetry.StatusCode:     "Internal",
						telemetry.StatusMessage:  "failed to create entry: creating error",
					},
				},
			},
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to create entry: creating error",
					},
				},
			},

			reqEntries:      []*types.Entry{testEntry},
			expectDsEntries: map[string]*common.RegistrationEntry{"entry1": testDSEntry},
			dsError:         errors.New("creating error"),
			dsResults:       map[string]*common.RegistrationEntry{"entry1": nil},
		},
		{
			name: "ds returns malformed entry",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to convert entry",
					Data: logrus.Fields{
						logrus.ErrorKey:    "invalid SPIFFE ID: scheme is missing or invalid",
						telemetry.SPIFFEID: "spiffe://example.org/workload",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status: "error",
						telemetry.Type:   "audit",

						telemetry.Admin:          "true",
						telemetry.DNSName:        "dns1",
						telemetry.Downstream:     "true",
						telemetry.RegistrationID: "entry1",
						telemetry.ExpiresAt:      strconv.FormatInt(testEntry.ExpiresAt, 10),
						telemetry.FederatesWith:  "domain1.org",
						telemetry.ParentID:       "spiffe://example.org/host",
						telemetry.RevisionNumber: "0",
						telemetry.Selectors:      "type:value1,type:value2",
						telemetry.SPIFFEID:       "spiffe://example.org/workload",
						telemetry.X509SVIDTTL:    "45",
						telemetry.JWTSVIDTTL:     "30",
						telemetry.Hint:           "external",
						telemetry.CreatedAt:      "0",
						telemetry.StoreSvid:      "false",
						telemetry.StatusCode:     "Internal",
						telemetry.StatusMessage:  "failed to convert entry: invalid SPIFFE ID: scheme is missing or invalid",
					},
				},
			},
			expectResults: []*entryv1.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to convert entry: invalid SPIFFE ID: scheme is missing or invalid",
					},
				},
			},

			reqEntries:      []*types.Entry{testEntry},
			expectDsEntries: map[string]*common.RegistrationEntry{"entry1": testDSEntry},
			dsResults: map[string]*common.RegistrationEntry{"entry1": {
				ParentId: "spiffe://example.org/path",
				SpiffeId: "sparfe://invalid/scheme",
			}},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ds := newFakeDS(t)

			test := setupServiceTest(t, ds)
			defer test.Cleanup()

			// Create federated bundles, that we use on "FederatesWith"
			createFederatedBundles(t, ds)
			defaultEntryID := createTestEntries(t, ds, defaultEntry)[defaultEntry.SpiffeId].EntryId

			// Setup fake
			ds.customCreate = !tt.noCustomCreate
			ds.t = t
			ds.expectEntries = tt.expectDsEntries
			ds.results = tt.dsResults
			ds.err = tt.dsError

			// Batch create entry
			resp, err := test.client.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{
				Entries:    tt.reqEntries,
				OutputMask: tt.outputMask,
			})

			require.NoError(t, err)
			require.NotNil(t, resp)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)

			for i, res := range tt.expectResults {
				if res.Entry != nil && res.Entry.Id == useDefaultEntryID {
					tt.expectResults[i].Entry.Id = defaultEntryID
				}
			}

			spiretest.AssertProtoEqual(t, &entryv1.BatchCreateEntryResponse{
				Results: tt.expectResults,
			}, resp)
		})
	}
}

func TestBatchDeleteEntry(t *testing.T) {
	expiresAt := time.Now().Unix()
	parentID := spiffeid.RequireFromSegments(td, "host").String()

	fooSpiffeID := spiffeid.RequireFromSegments(td, "foo").String()
	fooEntry := &common.RegistrationEntry{
		ParentId:    parentID,
		SpiffeId:    fooSpiffeID,
		Selectors:   []*common.Selector{{Type: "not", Value: "relevant"}},
		EntryExpiry: expiresAt,
	}
	barSpiffeID := spiffeid.RequireFromSegments(td, "bar").String()
	barEntry := &common.RegistrationEntry{
		ParentId:    parentID,
		SpiffeId:    barSpiffeID,
		Selectors:   []*common.Selector{{Type: "not", Value: "relevant"}},
		EntryExpiry: expiresAt,
	}
	bazSpiffeID := spiffeid.RequireFromSegments(td, "baz").String()
	baz := &common.RegistrationEntry{
		ParentId:    parentID,
		SpiffeId:    bazSpiffeID,
		Selectors:   []*common.Selector{{Type: "not", Value: "relevant"}},
		EntryExpiry: expiresAt,
	}

	dsEntries := []string{barSpiffeID, bazSpiffeID, fooSpiffeID}

	for _, tt := range []struct {
		name         string
		dsError      error
		expectDs     []string
		expectResult func(map[string]*common.RegistrationEntry) ([]*entryv1.BatchDeleteEntryResponse_Result, []spiretest.LogEntry)
		ids          func(map[string]*common.RegistrationEntry) []string
	}{
		{
			name:     "delete multiple entries",
			expectDs: []string{bazSpiffeID},
			expectResult: func(m map[string]*common.RegistrationEntry) ([]*entryv1.BatchDeleteEntryResponse_Result, []spiretest.LogEntry) {
				var results []*entryv1.BatchDeleteEntryResponse_Result
				results = append(results, &entryv1.BatchDeleteEntryResponse_Result{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Id:     m[fooSpiffeID].EntryId,
				})
				results = append(results, &entryv1.BatchDeleteEntryResponse_Result{
					Status: &types.Status{
						Code:    int32(codes.NotFound),
						Message: "entry not found",
					},
					Id: "not found",
				})
				results = append(results, &entryv1.BatchDeleteEntryResponse_Result{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Id:     m[barSpiffeID].EntryId,
				})

				expectedLogs := []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[fooSpiffeID].EntryId,
						},
					},
					{
						Level:   logrus.ErrorLevel,
						Message: "Entry not found",
						Data: logrus.Fields{
							telemetry.RegistrationID: "not found",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: "not found",
							telemetry.StatusCode:     "NotFound",
							telemetry.StatusMessage:  "entry not found",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[barSpiffeID].EntryId,
						},
					},
				}
				return results, expectedLogs
			},
			ids: func(m map[string]*common.RegistrationEntry) []string {
				return []string{m[fooSpiffeID].EntryId, "not found", m[barSpiffeID].EntryId}
			},
		},
		{
			name:     "no entries to delete",
			expectDs: dsEntries,
			expectResult: func(m map[string]*common.RegistrationEntry) ([]*entryv1.BatchDeleteEntryResponse_Result, []spiretest.LogEntry) {
				return []*entryv1.BatchDeleteEntryResponse_Result{}, nil
			},
			ids: func(m map[string]*common.RegistrationEntry) []string {
				return []string{}
			},
		},
		{
			name:     "missing entry ID",
			expectDs: dsEntries,
			expectResult: func(m map[string]*common.RegistrationEntry) ([]*entryv1.BatchDeleteEntryResponse_Result, []spiretest.LogEntry) {
				return []*entryv1.BatchDeleteEntryResponse_Result{
						{
							Status: &types.Status{
								Code:    int32(codes.InvalidArgument),
								Message: "missing entry ID",
							},
						},
					}, []spiretest.LogEntry{
						{
							Level:   logrus.ErrorLevel,
							Message: "Invalid argument: missing entry ID",
						},
						{
							Level:   logrus.InfoLevel,
							Message: "API accessed",
							Data: logrus.Fields{
								telemetry.Status:         "error",
								telemetry.Type:           "audit",
								telemetry.RegistrationID: "",
								telemetry.StatusCode:     "InvalidArgument",
								telemetry.StatusMessage:  "missing entry ID",
							},
						},
					}
			},
			ids: func(m map[string]*common.RegistrationEntry) []string {
				return []string{""}
			},
		},
		{
			name:     "fail to delete entry",
			dsError:  errors.New("some error"),
			expectDs: dsEntries,
			expectResult: func(m map[string]*common.RegistrationEntry) ([]*entryv1.BatchDeleteEntryResponse_Result, []spiretest.LogEntry) {
				return []*entryv1.BatchDeleteEntryResponse_Result{
						{
							Status: &types.Status{
								Code:    int32(codes.Internal),
								Message: "failed to delete entry: some error",
							},
							Id: m[fooSpiffeID].EntryId,
						},
					}, []spiretest.LogEntry{
						{
							Level:   logrus.ErrorLevel,
							Message: "Failed to delete entry",
							Data: logrus.Fields{
								telemetry.RegistrationID: m[fooSpiffeID].EntryId,
								logrus.ErrorKey:          "some error",
							},
						},
						{
							Level:   logrus.InfoLevel,
							Message: "API accessed",
							Data: logrus.Fields{
								telemetry.Status:         "error",
								telemetry.Type:           "audit",
								telemetry.RegistrationID: m[fooSpiffeID].EntryId,
								telemetry.StatusCode:     "Internal",
								telemetry.StatusMessage:  "failed to delete entry: some error",
							},
						},
					}
			},
			ids: func(m map[string]*common.RegistrationEntry) []string {
				return []string{m[fooSpiffeID].EntryId}
			},
		},
		{
			name:     "entry not found",
			expectDs: dsEntries,
			expectResult: func(m map[string]*common.RegistrationEntry) ([]*entryv1.BatchDeleteEntryResponse_Result, []spiretest.LogEntry) {
				return []*entryv1.BatchDeleteEntryResponse_Result{
						{
							Status: &types.Status{
								Code:    int32(codes.NotFound),
								Message: "entry not found",
							},
							Id: "invalid id",
						},
					}, []spiretest.LogEntry{
						{
							Level:   logrus.ErrorLevel,
							Message: "Entry not found",
							Data: logrus.Fields{
								telemetry.RegistrationID: "invalid id",
							},
						},
						{
							Level:   logrus.InfoLevel,
							Message: "API accessed",
							Data: logrus.Fields{
								telemetry.Status:         "error",
								telemetry.Type:           "audit",
								telemetry.RegistrationID: "invalid id",
								telemetry.StatusCode:     "NotFound",
								telemetry.StatusMessage:  "entry not found",
							},
						},
					}
			},
			ids: func(m map[string]*common.RegistrationEntry) []string {
				return []string{"invalid id"}
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ds := fakedatastore.New(t)
			test := setupServiceTest(t, ds)
			defer test.Cleanup()

			// Create entries
			entriesMap := createTestEntries(t, ds, fooEntry, barEntry, baz)

			ds.SetNextError(tt.dsError)
			resp, err := test.client.BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{
				Ids: tt.ids(entriesMap),
			})
			require.NoError(t, err)

			expectResults, expectLogs := tt.expectResult(entriesMap)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), expectLogs)
			spiretest.AssertProtoEqual(t, &entryv1.BatchDeleteEntryResponse{
				Results: expectResults,
			}, resp)

			// Validate DS contains expected entries
			listEntries, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
			require.NoError(t, err)

			var spiffeIDs []string
			for _, e := range listEntries.Entries {
				spiffeIDs = append(spiffeIDs, e.SpiffeId)
			}
			require.Equal(t, tt.expectDs, spiffeIDs)
		})
	}
}

func TestGetAuthorizedEntries(t *testing.T) {
	entry1 := types.Entry{
		Id:          "entry-1",
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
		X509SvidTtl: 60,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
		FederatesWith: []string{
			"domain1.com",
			"domain2.com",
		},
		Admin:      true,
		ExpiresAt:  time.Now().Add(30 * time.Second).Unix(),
		DnsNames:   []string{"dns1", "dns2"},
		Downstream: true,
		Hint:       "external",
		CreatedAt:  1678731397,
	}
	entry2 := types.Entry{
		Id:          "entry-2",
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/baz"},
		X509SvidTtl: 3600,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1001"},
			{Type: "unix", Value: "gid:1001"},
		},
		FederatesWith: []string{
			"domain3.com",
			"domain4.com",
		},
		ExpiresAt: time.Now().Add(60 * time.Second).Unix(),
		DnsNames:  []string{"dns3", "dns4"},
	}

	for _, tt := range []struct {
		name           string
		code           codes.Code
		fetcherErr     string
		err            string
		fetcherEntries []*types.Entry
		expectEntries  []*types.Entry
		expectLogs     []spiretest.LogEntry
		outputMask     *types.EntryMask
		failCallerID   bool
	}{
		{
			name:           "success",
			fetcherEntries: []*types.Entry{proto.Clone(&entry1).(*types.Entry), proto.Clone(&entry2).(*types.Entry)},
			expectEntries:  []*types.Entry{&entry1, &entry2},
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
			name:           "success, no entries",
			fetcherEntries: []*types.Entry{},
			expectEntries:  []*types.Entry{},
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
			name:           "success with output mask",
			fetcherEntries: []*types.Entry{proto.Clone(&entry1).(*types.Entry), proto.Clone(&entry2).(*types.Entry)},
			expectEntries: []*types.Entry{
				{
					Id:        entry1.Id,
					SpiffeId:  entry1.SpiffeId,
					ParentId:  entry1.ParentId,
					Selectors: entry1.Selectors,
				},
				{
					Id:        entry2.Id,
					SpiffeId:  entry2.SpiffeId,
					ParentId:  entry2.ParentId,
					Selectors: entry2.Selectors,
				},
			},
			outputMask: &types.EntryMask{
				SpiffeId:  true,
				ParentId:  true,
				Selectors: true,
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
			name:           "success with output mask all false",
			fetcherEntries: []*types.Entry{proto.Clone(&entry1).(*types.Entry), proto.Clone(&entry2).(*types.Entry)},
			expectEntries: []*types.Entry{
				{
					Id: entry1.Id,
				},
				{
					Id: entry2.Id,
				},
			},
			outputMask: &types.EntryMask{},
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
			name:         "no caller id",
			err:          "caller ID missing from request context",
			code:         codes.Internal,
			failCallerID: true,
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
		},
		{
			name:       "error",
			err:        "failed to fetch entries",
			code:       codes.Internal,
			fetcherErr: "fetcher fails",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch entries",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = fetcher fails",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to fetch entries: fetcher fails",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, fakedatastore.New(t))
			defer test.Cleanup()

			test.omitCallerID = tt.failCallerID
			test.ef.entries = tt.fetcherEntries
			test.ef.err = tt.fetcherErr
			resp, err := test.client.GetAuthorizedEntries(ctx, &entryv1.GetAuthorizedEntriesRequest{
				OutputMask: tt.outputMask,
			})

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			expectResponse := &entryv1.GetAuthorizedEntriesResponse{
				Entries: tt.expectEntries,
			}
			spiretest.AssertProtoEqual(t, expectResponse, resp)
		})
	}
}

func TestSyncAuthorizedEntries(t *testing.T) {
	entry1 := &types.Entry{
		Id:          "entry-1",
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
		X509SvidTtl: 10,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
		FederatesWith: []string{
			"domain1.com",
			"domain2.com",
		},
		Admin:          true,
		ExpiresAt:      time.Now().Add(10 * time.Second).Unix(),
		DnsNames:       []string{"dns1", "dns2"},
		Downstream:     true,
		RevisionNumber: 1,
	}
	entry2 := &types.Entry{
		Id:          "entry-2",
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/baz"},
		X509SvidTtl: 20,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1001"},
			{Type: "unix", Value: "gid:1001"},
		},
		FederatesWith: []string{
			"domain3.com",
			"domain4.com",
		},
		ExpiresAt:      time.Now().Add(20 * time.Second).Unix(),
		DnsNames:       []string{"dns3", "dns4"},
		RevisionNumber: 2,
	}
	entry3 := &types.Entry{
		Id:          "entry-3",
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/buz"},
		X509SvidTtl: 30,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1002"},
			{Type: "unix", Value: "gid:1002"},
		},
		FederatesWith: []string{
			"domain5.com",
			"domain6.com",
		},
		ExpiresAt:      time.Now().Add(30 * time.Second).Unix(),
		DnsNames:       []string{"dns5", "dns6"},
		RevisionNumber: 3,
	}

	type step struct {
		req  *entryv1.SyncAuthorizedEntriesRequest
		resp *entryv1.SyncAuthorizedEntriesResponse
		err  string
		code codes.Code
	}

	for _, tt := range []struct {
		name              string
		code              codes.Code
		fetcherErr        string
		authorizedEntries []*types.Entry
		steps             []step
		expectLogs        []spiretest.LogEntry
		omitCallerID      bool
	}{
		{
			name:              "success no paging",
			authorizedEntries: []*types.Entry{entry1, entry2},
			steps: []step{
				{
					req: &entryv1.SyncAuthorizedEntriesRequest{},
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						Entries: []*types.Entry{entry1, entry2},
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
			name:              "success with paging",
			authorizedEntries: []*types.Entry{entry2, entry3, entry1},
			steps: []step{
				// Sends initial request and gets back first page of sparse entries
				{
					req: &entryv1.SyncAuthorizedEntriesRequest{},
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						EntryRevisions: []*entryv1.EntryRevision{
							{Id: "entry-2", RevisionNumber: 2},
							{Id: "entry-3", RevisionNumber: 3},
						},
						More: true,
					},
				},
				// Gets back second page of sparse entries
				{
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						EntryRevisions: []*entryv1.EntryRevision{
							{Id: "entry-1", RevisionNumber: 1},
						},
						More: false,
					},
				},
				// Requests all entries and gets back first page of full entries
				{
					req: &entryv1.SyncAuthorizedEntriesRequest{
						Ids: []string{"entry-3", "entry-1", "entry-2"},
					},
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						Entries: []*types.Entry{entry1, entry2},
						More:    true,
					},
				},
				// Gets back second page of full entries
				{
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						Entries: []*types.Entry{entry3},
						More:    false,
					},
				},
				// Requests one full page of entries and gets back only page
				{
					req: &entryv1.SyncAuthorizedEntriesRequest{
						Ids: []string{"entry-1", "entry-3"},
					},
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						Entries: []*types.Entry{entry1, entry3},
						More:    false,
					},
				},
				// Requests less than a page of entries and gets back only page
				{
					req: &entryv1.SyncAuthorizedEntriesRequest{
						Ids: []string{"entry-2"},
					},
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						Entries: []*types.Entry{entry2},
						More:    false,
					},
				},
				// Requests entry that does not exist
				{
					req: &entryv1.SyncAuthorizedEntriesRequest{
						Ids: []string{"entry-4"},
					},
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						Entries: nil,
						More:    false,
					},
				},
				// Request a page and a half but middle does not exist
				{
					req: &entryv1.SyncAuthorizedEntriesRequest{
						Ids: []string{"entry-1", "entry-4", "entry-3"},
					},
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						Entries: []*types.Entry{entry1, entry3},
						More:    false,
					},
				},
				// Request a page and a half but end does not exist
				{
					req: &entryv1.SyncAuthorizedEntriesRequest{
						Ids: []string{"entry-1", "entry-3", "entry-4"},
					},
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						Entries: []*types.Entry{entry1, entry3},
						More:    false,
					},
				},
				// Request nothing
				{
					req: &entryv1.SyncAuthorizedEntriesRequest{},
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						Entries: nil,
						More:    false,
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
			name:              "success, no entries",
			authorizedEntries: []*types.Entry{},
			steps: []step{
				{
					req:  &entryv1.SyncAuthorizedEntriesRequest{},
					resp: &entryv1.SyncAuthorizedEntriesResponse{},
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
			name:              "success with output mask",
			authorizedEntries: []*types.Entry{entry1, entry2},
			steps: []step{
				{
					req: &entryv1.SyncAuthorizedEntriesRequest{
						OutputMask: &types.EntryMask{
							SpiffeId:       true,
							ParentId:       true,
							Selectors:      true,
							RevisionNumber: true,
						},
					},
					resp: &entryv1.SyncAuthorizedEntriesResponse{
						Entries: []*types.Entry{
							{
								Id:             entry1.Id,
								SpiffeId:       entry1.SpiffeId,
								ParentId:       entry1.ParentId,
								Selectors:      entry1.Selectors,
								RevisionNumber: entry1.RevisionNumber,
							},
							{
								Id:             entry2.Id,
								SpiffeId:       entry2.SpiffeId,
								ParentId:       entry2.ParentId,
								Selectors:      entry2.Selectors,
								RevisionNumber: entry2.RevisionNumber,
							},
						},
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
			name: "output mask excludes revision number",
			steps: []step{
				{
					req:  &entryv1.SyncAuthorizedEntriesRequest{OutputMask: &types.EntryMask{}},
					err:  "revision number cannot be masked",
					code: codes.InvalidArgument,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "revision number cannot be masked",
					},
				},
			},
		},
		{
			name: "no caller id",
			steps: []step{
				{
					err:  "caller ID missing from request context",
					code: codes.Internal,
				},
			},
			omitCallerID: true,
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
		},
		{
			name: "fetcher fails",
			steps: []step{
				{
					err:  "failed to fetch entries",
					code: codes.Internal,
				},
			},
			fetcherErr: "fetcher fails",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch entries",
					Data: logrus.Fields{
						logrus.ErrorKey: "rpc error: code = Internal desc = fetcher fails",
					},
				},
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "failed to fetch entries: fetcher fails",
					},
				},
			},
		},
		{
			name: "initial request specifies IDs",
			steps: []step{
				{
					req:  &entryv1.SyncAuthorizedEntriesRequest{Ids: []string{"entry-1"}},
					err:  "specifying IDs on initial request is not supported",
					code: codes.InvalidArgument,
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.InfoLevel,
					Message: "API accessed",
					Data: logrus.Fields{
						telemetry.Status:        "error",
						telemetry.Type:          "audit",
						telemetry.StatusCode:    "InvalidArgument",
						telemetry.StatusMessage: "specifying IDs on initial request is not supported",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, fakedatastore.New(t))
			defer func() {
				test.Cleanup()
				spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			}()

			test.omitCallerID = tt.omitCallerID
			test.ef.entries = tt.authorizedEntries
			test.ef.err = tt.fetcherErr

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			stream, err := test.client.SyncAuthorizedEntries(ctx)
			require.NoError(t, err)

			for i, step := range tt.steps {
				t.Logf("stream step: %d", i)
				if step.req != nil {
					require.NoError(t, stream.Send(step.req))
				}
				resp, err := stream.Recv()
				if step.err != "" {
					spiretest.RequireGRPCStatusContains(t, err, step.code, step.err)
					require.Nil(t, resp)
					return
				}
				require.NoError(t, err)
				spiretest.AssertProtoEqual(t, step.resp, resp)
			}
			require.NoError(t, stream.CloseSend())
		})
	}
}

func FuzzSyncAuthorizedStreams(f *testing.F) {
	rnd := rand.New(rand.NewSource(time.Now().Unix())) //nolint: gosec // this rand source ok for fuzz tests

	const entryPageSize = 5

	calculatePageCount := func(entries int) int {
		return (entries + (entryPageSize - 1)) / entryPageSize
	}
	recvNoError := func(tb testing.TB, stream entryv1.Entry_SyncAuthorizedEntriesClient) *entryv1.SyncAuthorizedEntriesResponse {
		resp, err := stream.Recv()
		require.NoError(tb, err)
		return resp
	}
	recvEOF := func(tb testing.TB, stream entryv1.Entry_SyncAuthorizedEntriesClient) {
		_, err := stream.Recv()
		require.True(tb, errors.Is(err, io.EOF))
	}

	const maxEntries = 40
	var entries []*types.Entry
	for i := range maxEntries {
		entries = append(entries, &types.Entry{Id: strconv.Itoa(i), RevisionNumber: 1})
	}

	// Add some quick boundary conditions as seeds that will be run
	// during standard testing.
	f.Add(0, 0)
	f.Add(1, 1)
	f.Add(entryPageSize-1, entryPageSize-1)
	f.Add(entryPageSize, entryPageSize)
	f.Add(entryPageSize+1, entryPageSize+1)
	f.Add(0, maxEntries)
	f.Add(maxEntries/2, maxEntries)
	f.Add(maxEntries, maxEntries)

	f.Fuzz(func(t *testing.T, staleEntries, totalEntries int) {
		if totalEntries < 0 || totalEntries > maxEntries {
			t.Skip()
		}
		if staleEntries < 0 || staleEntries > totalEntries {
			t.Skip()
		}

		entries := entries[:totalEntries]

		test := setupServiceTest(t, fakedatastore.New(t), withEntryPageSize(entryPageSize))
		defer test.Cleanup()
		test.ef.entries = entries

		ctx, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)

		// Open the stream and send the first request
		stream, err := test.client.SyncAuthorizedEntries(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(&entryv1.SyncAuthorizedEntriesRequest{}))

		revisionsExpected := totalEntries > entryPageSize

		if !revisionsExpected {
			// The number of entries does not exceed the page size. Expect
			// the full list of entries in a single response.
			resp := recvNoError(t, stream)
			require.Empty(t, resp.EntryRevisions)
			require.Equal(t, getEntryIDs(entries), getEntryIDs(resp.Entries))
			recvEOF(t, stream)
			return
		}

		// The number of entries exceeded the page size. Expect one or more
		// pages of entry revisions.
		var actualIDs []string
		for range calculatePageCount(totalEntries) - 1 {
			resp := recvNoError(t, stream)
			require.Equal(t, len(resp.EntryRevisions), entryPageSize)
			require.Zero(t, resp.Entries)
			require.True(t, resp.More)
			actualIDs = appendEntryIDs(actualIDs, resp.EntryRevisions)
		}
		resp := recvNoError(t, stream)
		require.LessOrEqual(t, len(resp.EntryRevisions), entryPageSize)
		require.Zero(t, resp.Entries)
		require.False(t, resp.More)
		actualIDs = appendEntryIDs(actualIDs, resp.EntryRevisions)

		// Build and request a shuffled list of stale entry IDs. Shuffling
		// helps exercise the searching logic in the handler though the actual
		// agent sends them sorted for better performance.
		staleIDs := getEntryIDs(entries)
		require.Equal(t, staleIDs, actualIDs)
		rnd.Shuffle(len(staleIDs), func(i, j int) { staleIDs[i], staleIDs[j] = staleIDs[j], staleIDs[i] })
		staleIDs = staleIDs[:staleEntries]
		require.NoError(t, stream.Send(&entryv1.SyncAuthorizedEntriesRequest{Ids: staleIDs}))

		actualIDs = actualIDs[:0]
		for range calculatePageCount(len(staleIDs)) - 1 {
			resp = recvNoError(t, stream)
			require.Equal(t, len(resp.Entries), entryPageSize)
			require.Zero(t, resp.EntryRevisions)
			require.True(t, resp.More)
			actualIDs = appendEntryIDs(actualIDs, resp.Entries)
		}
		resp = recvNoError(t, stream)
		require.LessOrEqual(t, len(resp.Entries), entryPageSize)
		require.Zero(t, resp.EntryRevisions)
		require.False(t, resp.More)
		actualIDs = appendEntryIDs(actualIDs, resp.Entries)

		// Ensure that all the entries were received that were requested
		sort.Strings(staleIDs)
		require.Equal(t, staleIDs, actualIDs)

		require.NoError(t, stream.CloseSend())
		recvEOF(t, stream)
	})
}

func TestBatchUpdateEntry(t *testing.T) {
	now := time.Now().Unix()
	parent := &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"}
	entry1SpiffeID := &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"}
	expiresAt := time.Now().Unix()
	initialEntry := &types.Entry{
		ParentId:    parent,
		SpiffeId:    entry1SpiffeID,
		X509SvidTtl: 60,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "uid:2000"},
		},
		FederatesWith: []string{
			federatedTd.Name(),
		},
		Admin:      true,
		ExpiresAt:  expiresAt,
		DnsNames:   []string{"dns1", "dns2"},
		Downstream: true,
	}
	storeSvidEntry := &types.Entry{
		ParentId:    parent,
		SpiffeId:    entry1SpiffeID,
		X509SvidTtl: 60,
		StoreSvid:   true,
		Selectors: []*types.Selector{
			{Type: "typ", Value: "key1:value"},
			{Type: "typ", Value: "key2:value"},
		},
		FederatesWith: []string{
			federatedTd.Name(),
		},
		ExpiresAt: expiresAt,
	}
	updateEverythingEntry := &types.Entry{
		ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/validUpdated"},
		SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/validUpdated"},
		X509SvidTtl: 400000,
		JwtSvidTtl:  300000,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:9999"},
		},
		FederatesWith: []string{},
		Admin:         false,
		ExpiresAt:     999999999,
		DnsNames:      []string{"dns3", "dns4"},
		Downstream:    false,
		Hint:          "newHint",
	}
	for _, tt := range []struct {
		name            string
		code            codes.Code
		dsError         error
		err             string
		expectDsEntries func(m string) []*types.Entry
		expectLogs      func(map[string]string) []spiretest.LogEntry
		expectStatus    *types.Status
		inputMask       *types.EntryMask
		outputMask      *types.EntryMask
		initialEntries  []*types.Entry
		updateEntries   []*types.Entry
		expectResults   []*entryv1.BatchUpdateEntryResponse_Result
	}{
		{
			name:           "Success Update Parent Id",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				ParentId: true,
			},
			outputMask: &types.EntryMask{
				ParentId: true,
			},
			updateEntries: []*types.Entry{
				{
					ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/parentUpdated"},
				},
			},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = id
				modifiedEntry.ParentId = &types.SPIFFEID{TrustDomain: "example.org", Path: "/parentUpdated"}
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/parentUpdated"},
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.ParentID:       "spiffe://example.org/parentUpdated",
						},
					},
				}
			},
		},
		{
			name:           "Success Update Spiffe Id",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				SpiffeId: true,
			},
			outputMask: &types.EntryMask{
				SpiffeId: true,
			},
			updateEntries: []*types.Entry{
				{
					SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workloadUpdated"},
				},
			},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = id
				modifiedEntry.SpiffeId = &types.SPIFFEID{TrustDomain: "example.org", Path: "/workloadUpdated"}
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workloadUpdated"},
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.SPIFFEID:       "spiffe://example.org/workloadUpdated",
						},
					},
				}
			},
		},
		{
			name:           "Success Update Multiple Selectors Into One",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				Selectors: true,
			},
			outputMask: &types.EntryMask{
				Selectors: true,
			},
			updateEntries: []*types.Entry{
				{
					Selectors: []*types.Selector{
						{Type: "unix", Value: "uid:2000"},
					},
				},
			},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = id
				// Annoying -- the selectors switch order inside api.ProtoToRegistrationEntry, so the
				// datastore won't return them in order
				// To avoid this, for this test, we only have one selector
				// In the next test, we test multiple selectors, and just don't verify against the data
				// store
				modifiedEntry.Selectors = []*types.Selector{
					{Type: "unix", Value: "uid:2000"},
				}
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Selectors: []*types.Selector{
							{Type: "unix", Value: "uid:2000"},
						},
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.Selectors:      "unix:uid:2000",
						},
					},
				}
			},
		},
		{
			name:           "Success Update Multiple Selectors",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				Selectors: true,
			},
			outputMask: &types.EntryMask{
				Selectors: true,
			},
			updateEntries: []*types.Entry{
				{
					Selectors: []*types.Selector{
						{Type: "unix", Value: "uid:2000"},
						{Type: "unix", Value: "gid:2000"},
					},
				},
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Selectors: []*types.Selector{
							{Type: "unix", Value: "gid:2000"},
							{Type: "unix", Value: "uid:2000"},
						},
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.Selectors:      "unix:uid:2000,unix:gid:2000",
						},
					},
				}
			},
		},
		{
			name:           "Success Update StoreSVID with Selectors",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				StoreSvid: true,
				Selectors: true,
			},
			outputMask: &types.EntryMask{
				StoreSvid: true,
				Selectors: true,
			},
			updateEntries: []*types.Entry{
				{
					StoreSvid: true,
					Selectors: []*types.Selector{
						{Type: "type", Value: "key1:value"},
						{Type: "type", Value: "key2:value"},
					},
				},
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						StoreSvid: true,
						Selectors: []*types.Selector{
							{Type: "type", Value: "key1:value"},
							{Type: "type", Value: "key2:value"},
						},
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.Selectors:      "type:key1:value,type:key2:value",
							telemetry.StoreSvid:      "true",
						},
					},
				}
			},
		},
		{
			name:           "Success Update from StoreSVID to normal",
			initialEntries: []*types.Entry{storeSvidEntry},
			inputMask: &types.EntryMask{
				StoreSvid: true,
				Selectors: true,
			},
			outputMask: &types.EntryMask{
				StoreSvid: true,
				Selectors: true,
			},
			updateEntries: []*types.Entry{
				{
					StoreSvid: false,
					Selectors: []*types.Selector{
						{Type: "type1", Value: "key1:value"},
						{Type: "type2", Value: "key2:value"},
					},
				},
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						StoreSvid: false,
						Selectors: []*types.Selector{
							{Type: "type1", Value: "key1:value"},
							{Type: "type2", Value: "key2:value"},
						},
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.Selectors:      "type1:key1:value,type2:key2:value",
							telemetry.StoreSvid:      "false",
						},
					},
				}
			},
		},
		{
			name:           "Success Update X509SVIDTTL",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				X509SvidTtl: true,
			},
			outputMask: &types.EntryMask{
				X509SvidTtl: true,
			},
			updateEntries: []*types.Entry{
				{
					X509SvidTtl: 1000,
				},
			},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = id
				modifiedEntry.X509SvidTtl = 1000
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						X509SvidTtl: 1000,
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.X509SVIDTTL:    "1000",
						},
					},
				}
			},
		},
		{
			name:           "Success Update FederatesWith",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				FederatesWith: true,
			},
			outputMask: &types.EntryMask{
				FederatesWith: true,
			},
			updateEntries: []*types.Entry{
				{
					FederatesWith: []string{},
				},
			},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = id
				modifiedEntry.FederatesWith = []string{}
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						FederatesWith: []string{},
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
						},
					},
				}
			},
		},
		{
			name:           "Success Update Admin",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				Admin: true,
			},
			outputMask: &types.EntryMask{
				Admin: true,
			},
			updateEntries: []*types.Entry{
				{
					Admin: false,
				},
			},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = id
				modifiedEntry.Admin = false
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Admin: false,
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.Admin:          "false",
						},
					},
				}
			},
		},
		{
			name:           "Success Update Downstream",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				Downstream: true,
			},
			outputMask: &types.EntryMask{
				Downstream: true,
			},
			updateEntries: []*types.Entry{
				{
					Downstream: false,
				},
			},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = id
				modifiedEntry.Downstream = false
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Downstream: false,
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.Downstream:     "false",
						},
					},
				}
			},
		},
		{
			name:           "Success Update ExpiresAt",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				ExpiresAt: true,
			},
			outputMask: &types.EntryMask{
				ExpiresAt: true,
			},
			updateEntries: []*types.Entry{
				{
					ExpiresAt: 999,
				},
			},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = id
				modifiedEntry.ExpiresAt = 999
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						ExpiresAt: 999,
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.ExpiresAt:      "999",
						},
					},
				}
			},
		},
		{
			name:           "Success Update DnsNames",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				DnsNames: true,
			},
			outputMask: &types.EntryMask{
				DnsNames: true,
			},
			updateEntries: []*types.Entry{
				{
					DnsNames: []string{"dnsUpdated"},
				},
			},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = id
				modifiedEntry.DnsNames = []string{"dnsUpdated"}
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						DnsNames: []string{"dnsUpdated"},
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.DNSName:        "dnsUpdated",
						},
					},
				}
			},
		},
		{
			name:           "Success Update Hint",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				Hint: true,
			},
			outputMask: &types.EntryMask{
				Hint: true,
			},
			updateEntries: []*types.Entry{
				{
					Hint: "newHint",
				},
			},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = id
				modifiedEntry.Hint = "newHint"
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Hint: "newHint",
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.Hint:           "newHint",
						},
					},
				}
			},
		},
		{
			name:           "Success Don't Update X509SVIDTTL",
			initialEntries: []*types.Entry{initialEntry},
			inputMask:      &types.EntryMask{
				// With this empty, the update operation should be a no-op
			},
			outputMask: &types.EntryMask{
				X509SvidTtl: true,
			},
			updateEntries: []*types.Entry{
				{
					X509SvidTtl: 500000,
				},
			},
			expectDsEntries: func(m string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = m
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						X509SvidTtl: 60,
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
						},
					},
				}
			},
		},
		{
			name:           "Fail StoreSvid with invalid Selectors",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				StoreSvid: true,
				Selectors: true,
			},
			updateEntries: []*types.Entry{
				{
					StoreSvid: true,
					Selectors: []*types.Selector{
						{Type: "type1", Value: "key1:value"},
						{Type: "type2", Value: "key2:value"},
					},
				},
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.InvalidArgument), Message: "failed to update entry: datastore-validation: invalid registration entry: selector types must be the same when store SVID is enabled"},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: failed to update entry",
						Data: logrus.Fields{
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							logrus.ErrorKey:          "rpc error: code = InvalidArgument desc = datastore-validation: invalid registration entry: selector types must be the same when store SVID is enabled",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.StatusCode:     "InvalidArgument",
							telemetry.StatusMessage:  "failed to update entry: datastore-validation: invalid registration entry: selector types must be the same when store SVID is enabled",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.Selectors:      "type1:key1:value,type2:key2:value",
							telemetry.StoreSvid:      "true",
						},
					},
				}
			},
		},
		{
			name:           "Fail Invalid Spiffe Id",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				SpiffeId: true,
			},
			updateEntries: []*types.Entry{
				{
					SpiffeId: &types.SPIFFEID{TrustDomain: "", Path: "/invalid"},
				},
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to convert entry: invalid spiffe ID: trust domain is missing",
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: failed to convert entry",
						Data: logrus.Fields{
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							logrus.ErrorKey:          "invalid spiffe ID: trust domain is missing",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.StatusCode:     "InvalidArgument",
							telemetry.StatusMessage:  "failed to convert entry: invalid spiffe ID: trust domain is missing",
						},
					},
				}
			},
		},
		{
			name:           "Fail Invalid Parent Id",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				ParentId: true,
			},
			updateEntries: []*types.Entry{
				{
					ParentId: &types.SPIFFEID{TrustDomain: "", Path: "/invalid"},
				},
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to convert entry: invalid parent ID: trust domain is missing",
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: failed to convert entry",
						Data: logrus.Fields{
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							logrus.ErrorKey:          "invalid parent ID: trust domain is missing",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.StatusCode:     "InvalidArgument",
							telemetry.StatusMessage:  "failed to convert entry: invalid parent ID: trust domain is missing",
						},
					},
				}
			},
		},
		{
			name:           "Fail Empty Parent Id",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				ParentId: true,
			},
			updateEntries: []*types.Entry{
				{
					ParentId: &types.SPIFFEID{TrustDomain: "", Path: ""},
				},
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to convert entry: invalid parent ID: trust domain is missing",
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: failed to convert entry",
						Data: logrus.Fields{
							"error":                  "invalid parent ID: trust domain is missing",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.StatusCode:     "InvalidArgument",
							telemetry.StatusMessage:  "failed to convert entry: invalid parent ID: trust domain is missing",
						},
					},
				}
			},
		},
		{
			name:           "Fail Empty Spiffe Id",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				SpiffeId: true,
			},
			updateEntries: []*types.Entry{
				{
					SpiffeId: &types.SPIFFEID{TrustDomain: "", Path: ""},
				},
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to convert entry: invalid spiffe ID: trust domain is missing",
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: failed to convert entry",
						Data: logrus.Fields{
							"error":                  "invalid spiffe ID: trust domain is missing",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.StatusCode:     "InvalidArgument",
							telemetry.StatusMessage:  "failed to convert entry: invalid spiffe ID: trust domain is missing",
						},
					},
				}
			},
		},
		{
			name:           "Fail Empty Selectors List",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				Selectors: true,
			},
			updateEntries: []*types.Entry{
				{
					Selectors: []*types.Selector{},
				},
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to convert entry: selector list is empty",
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: failed to convert entry",
						Data: logrus.Fields{
							"error":                  "selector list is empty",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.StatusCode:     "InvalidArgument",
							telemetry.StatusMessage:  "failed to convert entry: selector list is empty",
						},
					},
				}
			},
		},
		{
			name:           "Fail Datastore Error",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				ParentId: true,
			},
			updateEntries: []*types.Entry{
				{
					ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
				},
			},
			dsError: errors.New("datastore error"),
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.Internal), Message: "failed to update entry: datastore error"},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Failed to update entry",
						Data: logrus.Fields{
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							logrus.ErrorKey:          "datastore error",
						},
					},
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "error",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.StatusCode:     "Internal",
							telemetry.StatusMessage:  "failed to update entry: datastore error",
							telemetry.ParentID:       "spiffe://example.org/workload",
						},
					},
				}
			},
		},
		{
			name:           "Success Nil Input Mask",
			initialEntries: []*types.Entry{initialEntry},
			inputMask:      nil, // Nil should mean "update everything"
			outputMask:     nil,
			// Try to update all fields (all should be successfully updated)
			updateEntries: []*types.Entry{updateEverythingEntry},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(updateEverythingEntry).(*types.Entry)
				modifiedEntry.Id = id
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						ParentId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/validUpdated"},
						SpiffeId:    &types.SPIFFEID{TrustDomain: "example.org", Path: "/validUpdated"},
						X509SvidTtl: 400000,
						JwtSvidTtl:  300000,
						Selectors: []*types.Selector{
							{Type: "unix", Value: "uid:9999"},
						},
						FederatesWith:  []string{},
						Admin:          false,
						ExpiresAt:      999999999,
						DnsNames:       []string{"dns3", "dns4"},
						Downstream:     false,
						RevisionNumber: 1,
						Hint:           "newHint",
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.Admin:          "false",
							telemetry.DNSName:        "dns3,dns4",
							telemetry.Downstream:     "false",
							telemetry.ExpiresAt:      "999999999",
							telemetry.ParentID:       "spiffe://example.org/validUpdated",
							telemetry.RevisionNumber: "0",
							telemetry.Selectors:      "unix:uid:9999",
							telemetry.SPIFFEID:       "spiffe://example.org/validUpdated",
							telemetry.X509SVIDTTL:    "400000",
							telemetry.JWTSVIDTTL:     "300000",
							telemetry.StoreSvid:      "false",
							telemetry.Hint:           "newHint",
							telemetry.CreatedAt:      "0",
						},
					},
				}
			},
		},
		{
			name:           "Success Nil Output Mask",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				X509SvidTtl: true,
			},
			outputMask: nil,
			updateEntries: []*types.Entry{
				{
					X509SvidTtl: 500000,
				},
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						ParentId:    parent,
						SpiffeId:    entry1SpiffeID,
						X509SvidTtl: 500000,
						Selectors: []*types.Selector{
							{Type: "unix", Value: "uid:1000"},
							{Type: "unix", Value: "uid:2000"},
						},
						FederatesWith: []string{
							"domain1.org",
						},
						Admin:          true,
						ExpiresAt:      expiresAt,
						DnsNames:       []string{"dns1", "dns2"},
						Downstream:     true,
						RevisionNumber: 1,
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.X509SVIDTTL:    "500000",
						},
					},
				}
			},
		},
		{
			name:           "Success Empty Input Mask",
			initialEntries: []*types.Entry{initialEntry},
			inputMask:      &types.EntryMask{
				// With this empty, the update operation should be a no-op
			},
			outputMask: &types.EntryMask{
				SpiffeId: true,
			},
			// Try to update all fields (none will be updated)
			updateEntries: []*types.Entry{updateEverythingEntry},
			expectDsEntries: func(m string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = m
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
						},
					},
				}
			},
		},
		{
			name:           "Success Empty Output Mask",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				X509SvidTtl: true,
			},
			// With the output mask empty, the update will take place, but the results will be empty
			outputMask: &types.EntryMask{},
			updateEntries: []*types.Entry{
				{
					X509SvidTtl: 500000,
				},
			},
			expectDsEntries: func(m string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = m
				modifiedEntry.X509SvidTtl = 500000
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entryv1.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry:  &types.Entry{},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.InfoLevel,
						Message: "API accessed",
						Data: logrus.Fields{
							telemetry.Status:         "success",
							telemetry.Type:           "audit",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							telemetry.X509SVIDTTL:    "500000",
						},
					},
				}
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ds := fakedatastore.New(t)
			test := setupServiceTest(t, ds)
			defer test.Cleanup()
			// Create federated bundles, that we use on "FederatesWith"
			createFederatedBundles(t, test.ds)

			// First create the initial entries
			createResp, err := test.client.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{
				Entries: tt.initialEntries,
			})
			require.NoError(t, err)
			require.Equal(t, len(createResp.Results), len(tt.updateEntries))

			// Then copy the IDs of the created entries onto the entries to be updated
			spiffeToIDMap := make(map[string]string)
			updateEntries := tt.updateEntries
			for i := range createResp.Results {
				require.Equal(t, api.OK(), createResp.Results[i].Status)
				updateEntries[i].Id = createResp.Results[i].Entry.Id
				spiffeToIDMap[createResp.Results[i].Entry.SpiffeId.Path] = createResp.Results[i].Entry.Id
			}
			ds.SetNextError(tt.dsError)
			// Clean creation logs
			test.logHook.Reset()

			// Actually do the update, with the proper IDs
			resp, err := test.client.BatchUpdateEntry(ctx, &entryv1.BatchUpdateEntryRequest{
				Entries:    updateEntries,
				InputMask:  tt.inputMask,
				OutputMask: tt.outputMask,
			})
			require.NoError(t, err)

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs(spiffeToIDMap))
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				return
			}
			require.Equal(t, len(tt.updateEntries), len(resp.Results))

			// The updated entries contain IDs, which we don't know before running the test.
			// To make things easy we set all the IDs to empty before checking the results.
			for i := range resp.Results {
				if resp.Results[i].Entry != nil {
					resp.Results[i].Entry.Id = ""
					if tt.outputMask == nil || tt.outputMask.CreatedAt {
						assert.GreaterOrEqual(t, resp.Results[i].Entry.CreatedAt, now)
						resp.Results[i].Entry.CreatedAt = 0
					}
				}
			}

			spiretest.AssertProtoEqual(t, &entryv1.BatchUpdateEntryResponse{
				Results: tt.expectResults,
			}, resp)

			// Check that the datastore also contains the correctly updated entry
			// expectDsEntries is a function so it can substitute in the right entryID and make any needed changes
			// to the template itself
			// This only checks the first entry in the DS (which is fine since most test cases only update 1 entry)
			ds.SetNextError(nil)
			if tt.expectDsEntries != nil {
				listEntries, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
				require.NoError(t, err)
				firstEntry, err := api.RegistrationEntryToProto(listEntries.Entries[0])
				require.NoError(t, err)
				expectedEntry := tt.expectDsEntries(listEntries.Entries[0].EntryId)[0]
				assert.GreaterOrEqual(t, firstEntry.CreatedAt, now)
				firstEntry.CreatedAt = expectedEntry.CreatedAt
				spiretest.AssertProtoEqual(t, firstEntry, expectedEntry)
			}
		})
	}
}

func createFederatedBundles(t *testing.T, ds datastore.DataStore) {
	_, err := ds.CreateBundle(ctx, &common.Bundle{
		TrustDomainId: federatedTd.IDString(),
		RootCas: []*common.Certificate{
			{
				DerBytes: []byte("federated bundle"),
			},
		},
	})
	require.NoError(t, err)
	_, err = ds.CreateBundle(ctx, &common.Bundle{
		TrustDomainId: secondFederatedTd.IDString(),
		RootCas: []*common.Certificate{
			{
				DerBytes: []byte("second federated bundle"),
			},
		},
	})
	require.NoError(t, err)
}

func createTestEntries(t *testing.T, ds datastore.DataStore, entry ...*common.RegistrationEntry) map[string]*common.RegistrationEntry {
	entriesMap := make(map[string]*common.RegistrationEntry)

	for _, e := range entry {
		registrationEntry, err := ds.CreateRegistrationEntry(ctx, e)
		require.NoError(t, err)

		entriesMap[registrationEntry.SpiffeId] = registrationEntry
	}

	return entriesMap
}

type serviceTestOption = func(*serviceTestConfig)

func withEntryPageSize(v int) func(*serviceTestConfig) {
	return func(config *serviceTestConfig) {
		config.entryPageSize = v
	}
}

type serviceTestConfig struct {
	entryPageSize int
}

type serviceTest struct {
	client       entryv1.EntryClient
	ef           *entryFetcher
	done         func()
	ds           datastore.DataStore
	logHook      *test.Hook
	omitCallerID bool
}

func (s *serviceTest) Cleanup() {
	s.done()
}

func setupServiceTest(t *testing.T, ds datastore.DataStore, options ...serviceTestOption) *serviceTest {
	config := serviceTestConfig{
		entryPageSize: 2,
	}

	for _, opt := range options {
		opt(&config)
	}

	ef := &entryFetcher{}
	service := entry.New(entry.Config{
		TrustDomain:   td,
		DataStore:     ds,
		EntryFetcher:  ef,
		EntryPageSize: config.entryPageSize,
	})

	log, logHook := test.NewNullLogger()
	test := &serviceTest{
		ds:      ds,
		logHook: logHook,
		ef:      ef,
	}

	overrideContext := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		if !test.omitCallerID {
			ctx = rpccontext.WithCallerID(ctx, agentID)
		}
		return ctx
	}

	server := grpctest.StartServer(t, func(s grpc.ServiceRegistrar) {
		entry.RegisterService(s, service)
	},
		grpctest.OverrideContext(overrideContext),
		grpctest.Middleware(middleware.WithAuditLog(false)),
	)

	conn := server.NewGRPCClient(t)

	test.client = entryv1.NewEntryClient(conn)
	test.done = server.Stop

	return test
}

type fakeDS struct {
	*fakedatastore.DataStore

	t             *testing.T
	customCreate  bool
	err           error
	expectEntries map[string]*common.RegistrationEntry
	results       map[string]*common.RegistrationEntry
}

func newFakeDS(t *testing.T) *fakeDS {
	return &fakeDS{
		DataStore:     fakedatastore.New(t),
		expectEntries: make(map[string]*common.RegistrationEntry),
		results:       make(map[string]*common.RegistrationEntry),
	}
}

func (f *fakeDS) CreateOrReturnRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, bool, error) {
	if !f.customCreate {
		return f.DataStore.CreateOrReturnRegistrationEntry(ctx, entry)
	}

	if f.err != nil {
		return nil, false, f.err
	}
	entryID := entry.EntryId

	expect, ok := f.expectEntries[entryID]
	assert.True(f.t, ok, "no expect entry found for entry %q", entryID)

	// Validate we get expected entry
	assert.Zero(f.t, entry.CreatedAt)
	entry.CreatedAt = expect.CreatedAt
	spiretest.AssertProtoEqual(f.t, expect, entry)

	// Return expect when no custom result configured
	if len(f.results) == 0 {
		return expect, false, nil
	}

	res, ok := f.results[entryID]
	assert.True(f.t, ok, "no result found")

	return res, false, nil
}

type entryFetcher struct {
	err     string
	entries []*types.Entry
}

func (f *entryFetcher) FetchAuthorizedEntries(ctx context.Context, agentID spiffeid.ID) ([]*types.Entry, error) {
	if f.err != "" {
		return nil, status.Error(codes.Internal, f.err)
	}

	caller, ok := rpccontext.CallerID(ctx)
	if !ok {
		return nil, errors.New("missing caller ID")
	}

	if caller != agentID {
		return nil, fmt.Errorf("provided caller id is different to expected")
	}

	return f.entries, nil
}

type HasID interface {
	GetId() string
}

func getEntryIDs[T HasID](entries []T) []string {
	return appendEntryIDs([]string(nil), entries)
}

func appendEntryIDs[T HasID](ids []string, entries []T) []string {
	for _, entry := range entries {
		ids = append(ids, entry.GetId())
	}
	return ids
}
