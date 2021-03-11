package entry_test

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
	"github.com/spiffe/spire/pkg/server/api/entry/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	entrypb "github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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
		resp       *entrypb.CountEntriesResponse
		code       codes.Code
		dsError    error
		err        string
		expectLogs []spiretest.LogEntry
	}{
		{
			name:  "0 entries",
			count: 0,
			resp:  &entrypb.CountEntriesResponse{Count: 0},
		},
		{
			name:  "1 entries",
			count: 1,
			resp:  &entrypb.CountEntriesResponse{Count: 1},
		},
		{
			name:  "2 entries",
			count: 2,
			resp:  &entrypb.CountEntriesResponse{Count: 2},
		},
		{
			name:  "3 entries",
			count: 3,
			resp:  &entrypb.CountEntriesResponse{Count: 3},
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
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ds := fakedatastore.New(t)
			test := setupServiceTest(t, ds)
			defer test.Cleanup()

			for i := 0; i < int(tt.count); i++ {
				_, err := test.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
					Entry: &common.RegistrationEntry{
						ParentId: td.NewID(fmt.Sprintf("parent%d", i)).String(),
						SpiffeId: td.NewID(fmt.Sprintf("child%d", i)).String(),
						Selectors: []*common.Selector{
							{Type: "unix", Value: "uid:1000"},
							{Type: "unix", Value: "gid:1000"},
						},
					},
				})
				require.NoError(t, err)
			}

			ds.SetNextError(tt.dsError)
			resp, err := test.client.CountEntries(context.Background(), &entrypb.CountEntriesRequest{})

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
	parentID := td.NewID("parent")
	childID := td.NewID("child")
	secondChildID := td.NewID("second_child")

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
	}
	badRegEntry := &common.RegistrationEntry{
		ParentId: parentID.String(),
		SpiffeId: "zzz://malformed id",
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
	}

	// setup
	ds := fakedatastore.New(t)
	test := setupServiceTest(t, ds)
	defer test.Cleanup()

	// Create federated bundles, that we use on "FederatesWith"
	createFederatedBundles(t, test.ds)

	childEntry, err := test.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: childRegEntry,
	})
	require.NoError(t, err)
	require.NotNil(t, childEntry)

	secondChildEntry, err := test.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: secondChildRegEntry,
	})
	require.NoError(t, err)
	require.NotNil(t, secondChildEntry)

	badEntry, err := test.ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: badRegEntry,
	})
	require.NoError(t, err)
	require.NotNil(t, badEntry)

	// expected entries
	expectedChild := &types.Entry{
		Id:       childEntry.Entry.EntryId,
		ParentId: protoParentID,
		SpiffeId: protoChildID,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "gid:1000"},
			{Type: "unix", Value: "uid:1000"},
		},
		FederatesWith: []string{
			federatedTd.String(),
		},
	}

	expectedSecondChild := &types.Entry{
		Id:       secondChildEntry.Entry.EntryId,
		ParentId: protoParentID,
		SpiffeId: protoSecondChildID,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
		},
		FederatesWith: []string{
			federatedTd.String(),
			secondFederatedTd.String(),
		},
	}

	for _, tt := range []struct {
		name                  string
		err                   string
		code                  codes.Code
		logMsg                string
		dsError               error
		expectedNextPageToken string
		expectedEntries       []*types.Entry
		request               *entrypb.ListEntriesRequest
	}{
		{
			name: "happy path",
			expectedEntries: []*types.Entry{
				{
					Id:       childEntry.Entry.EntryId,
					SpiffeId: protoChildID,
				},
			},
			request: &entrypb.ListEntriesRequest{
				OutputMask: &types.EntryMask{
					SpiffeId: true,
				},
				Filter: &entrypb.ListEntriesRequest_Filter{
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
		},
		{
			name:            "empty request",
			logMsg:          "Failed to convert entry: ",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request:         &entrypb.ListEntriesRequest{},
		},
		{
			name:            "filter by parent ID",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByParentId: protoParentID,
				},
			},
		},
		{
			name:            "filter by SPIFFE ID",
			expectedEntries: []*types.Entry{expectedChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					BySpiffeId: protoChildID,
				},
			},
		},
		{
			name:            "filter by selectors exact match",
			expectedEntries: []*types.Entry{expectedSecondChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "unix", Value: "uid:1000"},
						},
						Match: types.SelectorMatch_MATCH_EXACT,
					},
				},
			},
		},
		{
			name:            "filter by selectors subset match",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
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
		},
		{
			name:            "filter by federates with exact match (no subset)",
			expectedEntries: []*types.Entry{expectedSecondChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.String(),
						},
						Match: types.FederatesWithMatch_MATCH_EXACT,
					},
				},
			},
		},
		{
			name:            "filter by federates with exact match (no superset)",
			expectedEntries: []*types.Entry{expectedChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							federatedTd.IDString(),
						},
						Match: types.FederatesWithMatch_MATCH_EXACT,
					},
				},
			},
		},
		{
			name:            "filter by federates with exact match (with repeated tds)",
			expectedEntries: []*types.Entry{expectedSecondChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.IDString(),
							secondFederatedTd.String(), // repeated td
						},
						Match: types.FederatesWithMatch_MATCH_EXACT,
					},
				},
			},
		},
		{
			name:            "filter by federates with exact match (not federated)",
			expectedEntries: []*types.Entry{},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							notFederatedTd.String(),
						},
						Match: types.FederatesWithMatch_MATCH_EXACT,
					},
				},
			},
		},
		{
			name:            "filter by federates with subset match",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.String(),
							notFederatedTd.IDString(),
						},
						Match: types.FederatesWithMatch_MATCH_SUBSET,
					},
				},
			},
		},
		{
			name:            "filter by federates with subset match (no superset)",
			expectedEntries: []*types.Entry{expectedChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							federatedTd.IDString(),
						},
						Match: types.FederatesWithMatch_MATCH_SUBSET,
					},
				},
			},
		},
		{
			name:            "filter by federates with subset match (with repeated tds)",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							// Both formats should work
							federatedTd.IDString(),
							secondFederatedTd.IDString(),
							secondFederatedTd.String(), // repeated td
						},
						Match: types.FederatesWithMatch_MATCH_SUBSET,
					},
				},
			},
		},
		{
			name:            "filter by federates with subset match (not federated)",
			expectedEntries: []*types.Entry{},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							notFederatedTd.String(),
						},
						Match: types.FederatesWithMatch_MATCH_SUBSET,
					},
				},
			},
		},
		{
			name:                  "page",
			expectedEntries:       []*types.Entry{expectedChild},
			expectedNextPageToken: "1",
			request: &entrypb.ListEntriesRequest{
				PageSize: 1,
			},
		},
		{
			name:    "ds error",
			err:     "failed to list entries: ds error",
			code:    codes.Internal,
			logMsg:  "Failed to list entries",
			dsError: errors.New("ds error"),
			request: &entrypb.ListEntriesRequest{},
		},
		{
			name:   "bad parent ID filter",
			err:    "malformed parent ID filter: trust domain is empty",
			code:   codes.InvalidArgument,
			logMsg: "Invalid argument: malformed parent ID filter",
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByParentId: badID,
				},
			},
		},
		{
			name:   "bad SPIFFE ID filter",
			err:    "malformed SPIFFE ID filter: trust domain is empty",
			code:   codes.InvalidArgument,
			logMsg: "Invalid argument: malformed SPIFFE ID filter",
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					BySpiffeId: badID,
				},
			},
		},
		{
			name:            "bad selectors filter (no selectors)",
			err:             "malformed selectors filter: empty selector set",
			code:            codes.InvalidArgument,
			logMsg:          "Invalid argument: malformed selectors filter",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{},
				},
			},
		},
		{
			name:   "bad selectors filter (bad selector)",
			err:    "malformed selectors filter: missing selector type",
			code:   codes.InvalidArgument,
			logMsg: "Invalid argument: malformed selectors filter",
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{
						Selectors: []*types.Selector{
							{Type: "", Value: "uid:1000"},
						},
					},
				},
			},
		},
		{
			name:   "bad federates with filter (no trust domains)",
			err:    "malformed federates with filter: empty trust domain set",
			code:   codes.InvalidArgument,
			logMsg: "Invalid argument: malformed federates with filter",
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{},
				},
			},
		},
		{
			name:   "bad federates with filter (bad trust domain)",
			err:    "malformed federates with filter: spiffeid: trust domain is empty",
			code:   codes.InvalidArgument,
			logMsg: "Invalid argument: malformed federates with filter",
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByFederatesWith: &types.FederatesWithMatch{
						TrustDomains: []string{
							badID.TrustDomain,
						},
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ds.SetNextError(tt.dsError)

			// exercise
			entries, err := test.client.ListEntries(context.Background(), tt.request)

			// assert
			if tt.logMsg != "" {
				require.Contains(t, test.logHook.LastEntry().Message, tt.logMsg)
			}

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
	ds := fakedatastore.New(t)
	test := setupServiceTest(t, ds)
	defer test.Cleanup()

	// Create fedeated bundles, that we use on "FederatesWith"
	createFederatedBundles(t, test.ds)

	parent := td.NewID("foo")
	entry1SpiffeID := td.NewID("bar")
	expiresAt := time.Now().Unix()
	goodEntry, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: &common.RegistrationEntry{
			ParentId: parent.String(),
			SpiffeId: entry1SpiffeID.String(),
			Ttl:      60,
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
		},
	})
	require.NoError(t, err)

	malformedEntry, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
		Entry: &common.RegistrationEntry{
			ParentId: parent.String(),
			SpiffeId: "malformed id",
			Selectors: []*common.Selector{
				{Type: "unix", Value: "uid:1000"},
			},
			EntryExpiry: expiresAt,
		},
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
			entryID: goodEntry.Entry.EntryId,
			expectEntry: &types.Entry{
				Id:       goodEntry.Entry.EntryId,
				ParentId: api.ProtoFromID(parent),
				SpiffeId: api.ProtoFromID(entry1SpiffeID),
			},
			outputMask: &types.EntryMask{
				ParentId: true,
				SpiffeId: true,
			},
		},
		{
			name:    "no outputMask",
			entryID: goodEntry.Entry.EntryId,
			expectEntry: &types.Entry{
				Id:       goodEntry.Entry.EntryId,
				ParentId: api.ProtoFromID(parent),
				SpiffeId: api.ProtoFromID(entry1SpiffeID),
				Ttl:      60,
				Selectors: []*types.Selector{
					{Type: "unix", Value: "uid:1000"},
					{Type: "unix", Value: "gid:1000"},
				},
				FederatesWith: []string{federatedTd.String()},
				Admin:         true,
				DnsNames:      []string{"dns1", "dns2"},
				Downstream:    true,
				ExpiresAt:     expiresAt,
			},
		},
		{
			name:        "outputMask all false",
			entryID:     goodEntry.Entry.EntryId,
			expectEntry: &types.Entry{Id: goodEntry.Entry.EntryId},
			outputMask:  &types.EntryMask{},
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
			},
		},
		{
			name:    "fetch fails",
			code:    codes.Internal,
			entryID: goodEntry.Entry.EntryId,
			err:     "failed to fetch entry: ds error",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch entry",
					Data: logrus.Fields{
						telemetry.RegistrationID: goodEntry.Entry.EntryId,
						logrus.ErrorKey:          "ds error",
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
			},
		},
		{
			name:    "malformed entry",
			code:    codes.Internal,
			entryID: malformedEntry.Entry.EntryId,
			err:     "failed to convert entry: invalid SPIFFE ID: spiffeid: invalid scheme",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to convert entry",
					Data: logrus.Fields{
						telemetry.RegistrationID: malformedEntry.Entry.EntryId,
						logrus.ErrorKey:          "invalid SPIFFE ID: spiffeid: invalid scheme",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()
			ds.SetNextError(tt.dsError)

			resp, err := test.client.GetEntry(ctx, &entrypb.GetEntryRequest{
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
			spiretest.AssertProtoEqual(t, tt.expectEntry, resp)
		})
	}
}

func TestBatchCreateEntry(t *testing.T) {
	entryParentID := td.NewID("foo")
	entrySpiffeID := td.NewID("bar")
	expiresAt := time.Now().Unix()

	useDefaultEntryID := "DEFAULT_ENTRY_ID"

	defaultEntry := &common.RegistrationEntry{
		ParentId: entryParentID.String(),
		SpiffeId: entrySpiffeID.String(),
		Ttl:      60,
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
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "host"},
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "workload"},
		Selectors: []*types.Selector{
			{Type: "type", Value: "value1"},
			{Type: "type", Value: "value2"},
		},
		Admin:         true,
		DnsNames:      []string{"dns1"},
		Downstream:    true,
		ExpiresAt:     expiresAt,
		FederatesWith: []string{"domain1.org"},
		Ttl:           60,
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
		Ttl:           60,
	}

	for _, tt := range []struct {
		name          string
		expectLogs    []spiretest.LogEntry
		expectResults []*entrypb.BatchCreateEntryResponse_Result
		expectStatus  *types.Status
		outputMask    *types.EntryMask
		reqEntries    []*types.Entry

		// fake ds configurations
		dsError         error
		dsResults       map[string]*common.RegistrationEntry
		expectDsEntries map[string]*common.RegistrationEntry
	}{
		{
			name: "multiple entries",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert entry",
					Data: logrus.Fields{
						logrus.ErrorKey: "invalid DNS name: empty or only whitespace",
					},
				},
			},
			expectResults: []*entrypb.BatchCreateEntryResponse_Result{
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
						Path:        "agent",
					},
					SpiffeId: &types.SPIFFEID{
						TrustDomain: "example.org",
						Path:        "/malformed",
					},
					Selectors: []*types.Selector{{Type: "type", Value: "value"}},
					DnsNames:  []string{""},
				}, {
					Id: "entry2",
					ParentId: &types.SPIFFEID{
						TrustDomain: "example.org",
						Path:        "agent",
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
			name: "no output mask",
			expectResults: []*entrypb.BatchCreateEntryResponse_Result{
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
						Ttl:           60,
					},
				},
			},
			reqEntries:      []*types.Entry{testEntry},
			expectDsEntries: map[string]*common.RegistrationEntry{"entry1": testDSEntry},
		},
		{
			name: "output mask all false",
			expectResults: []*entrypb.BatchCreateEntryResponse_Result{
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
		},
		{
			name:          "no entries to add",
			expectResults: []*entrypb.BatchCreateEntryResponse_Result{},
			reqEntries:    []*types.Entry{},
		},
		{
			name: "create with same parent ID and spiffe ID but different selectors",
			expectResults: []*entrypb.BatchCreateEntryResponse_Result{
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
					Id:       "entry1",
					ParentId: api.ProtoFromID(entryParentID),
					SpiffeId: api.ProtoFromID(entrySpiffeID),
					Ttl:      60,
					Selectors: []*types.Selector{
						{Type: "type", Value: "value1"},
					},
				},
			},
			expectDsEntries: map[string]*common.RegistrationEntry{
				"entry1": {
					EntryId:  "entry1",
					ParentId: "spiffe://example.org/foo",
					SpiffeId: "spiffe://example.org/bar",
					Ttl:      60,
					Selectors: []*common.Selector{
						{Type: "type", Value: "value1"},
					},
				},
			},
		},
		{
			name: "returns existing similar entry",
			expectResults: []*entrypb.BatchCreateEntryResponse_Result{
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
					ParentId: api.ProtoFromID(entryParentID),
					SpiffeId: api.ProtoFromID(entrySpiffeID),
					Ttl:      20,
					Admin:    false,
					Selectors: []*types.Selector{
						{Type: "unix", Value: "gid:1000"},
						{Type: "unix", Value: "uid:1000"},
					},
				},
			},
		},
		{
			name: "invalid entry",
			expectResults: []*entrypb.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.InvalidArgument),
						Message: "failed to convert entry: invalid parent ID: trust domain is empty",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid argument: failed to convert entry",
					Data: logrus.Fields{
						logrus.ErrorKey: "invalid parent ID: trust domain is empty",
					},
				},
			},
			reqEntries: []*types.Entry{
				{
					ParentId: &types.SPIFFEID{TrustDomain: "", Path: "path"},
				},
			},
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
			},
			expectResults: []*entrypb.BatchCreateEntryResponse_Result{
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
						logrus.ErrorKey:    "invalid SPIFFE ID: spiffeid: invalid scheme",
						telemetry.SPIFFEID: "spiffe://example.org/workload",
					},
				},
			},
			expectResults: []*entrypb.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "failed to convert entry: invalid SPIFFE ID: spiffeid: invalid scheme",
					},
				},
			},

			reqEntries:      []*types.Entry{testEntry},
			expectDsEntries: map[string]*common.RegistrationEntry{"entry1": testDSEntry},
			dsResults: map[string]*common.RegistrationEntry{"entry1": {
				ParentId: "spiffe://example.org/path",
				SpiffeId: "invalid id",
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
			ds.customCreate = true
			ds.t = t
			ds.expectEntries = tt.expectDsEntries
			ds.results = tt.dsResults
			ds.err = tt.dsError

			// Batch create entry
			resp, err := test.client.BatchCreateEntry(ctx, &entrypb.BatchCreateEntryRequest{
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

			spiretest.AssertProtoEqual(t, &entrypb.BatchCreateEntryResponse{
				Results: tt.expectResults,
			}, resp)
		})
	}
}

func TestBatchDeleteEntry(t *testing.T) {
	expiresAt := time.Now().Unix()
	parentID := td.NewID("host").String()

	fooSpiffeID := td.NewID("foo").String()
	fooEntry := &common.RegistrationEntry{
		ParentId:    parentID,
		SpiffeId:    fooSpiffeID,
		Selectors:   []*common.Selector{{Type: "not", Value: "relevant"}},
		EntryExpiry: expiresAt,
	}
	barSpiffeID := td.NewID("bar").String()
	barEntry := &common.RegistrationEntry{
		ParentId:    parentID,
		SpiffeId:    barSpiffeID,
		Selectors:   []*common.Selector{{Type: "not", Value: "relevant"}},
		EntryExpiry: expiresAt,
	}
	bazSpiffeID := td.NewID("baz").String()
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
		expectResult func(map[string]*common.RegistrationEntry) ([]*entrypb.BatchDeleteEntryResponse_Result, []spiretest.LogEntry)
		ids          func(map[string]*common.RegistrationEntry) []string
	}{
		{
			name:     "delete multiple entries",
			expectDs: []string{bazSpiffeID},
			expectResult: func(m map[string]*common.RegistrationEntry) ([]*entrypb.BatchDeleteEntryResponse_Result, []spiretest.LogEntry) {
				var results []*entrypb.BatchDeleteEntryResponse_Result
				results = append(results, &entrypb.BatchDeleteEntryResponse_Result{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Id:     m[fooSpiffeID].EntryId,
				})
				results = append(results, &entrypb.BatchDeleteEntryResponse_Result{
					Status: &types.Status{
						Code:    int32(codes.NotFound),
						Message: "entry not found",
					},
					Id: "not found",
				})
				results = append(results, &entrypb.BatchDeleteEntryResponse_Result{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Id:     m[barSpiffeID].EntryId,
				})

				expectedLogs := []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Entry not found",
						Data: logrus.Fields{
							telemetry.RegistrationID: "not found",
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
			expectResult: func(m map[string]*common.RegistrationEntry) ([]*entrypb.BatchDeleteEntryResponse_Result, []spiretest.LogEntry) {
				return []*entrypb.BatchDeleteEntryResponse_Result{}, nil
			},
			ids: func(m map[string]*common.RegistrationEntry) []string {
				return []string{}
			},
		},
		{
			name:     "missing entry ID",
			expectDs: dsEntries,
			expectResult: func(m map[string]*common.RegistrationEntry) ([]*entrypb.BatchDeleteEntryResponse_Result, []spiretest.LogEntry) {
				return []*entrypb.BatchDeleteEntryResponse_Result{
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
			expectResult: func(m map[string]*common.RegistrationEntry) ([]*entrypb.BatchDeleteEntryResponse_Result, []spiretest.LogEntry) {
				return []*entrypb.BatchDeleteEntryResponse_Result{
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
					}
			},
			ids: func(m map[string]*common.RegistrationEntry) []string {
				return []string{m[fooSpiffeID].EntryId}
			},
		},
		{
			name:     "entry not found",
			expectDs: dsEntries,
			expectResult: func(m map[string]*common.RegistrationEntry) ([]*entrypb.BatchDeleteEntryResponse_Result, []spiretest.LogEntry) {
				return []*entrypb.BatchDeleteEntryResponse_Result{
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
			resp, err := test.client.BatchDeleteEntry(ctx, &entrypb.BatchDeleteEntryRequest{
				Ids: tt.ids(entriesMap),
			})
			require.NoError(t, err)

			expectResults, expectLogs := tt.expectResult(entriesMap)
			spiretest.AssertLogs(t, test.logHook.AllEntries(), expectLogs)
			spiretest.AssertProtoEqual(t, &entrypb.BatchDeleteEntryResponse{
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
		Id:       "entry-1",
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/bar"},
		Ttl:      60,
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
	}
	entry2 := types.Entry{
		Id:       "entry-2",
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/foo"},
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/baz"},
		Ttl:      3600,
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
		},
		{
			name:           "success, no entries",
			fetcherEntries: []*types.Entry{},
			expectEntries:  []*types.Entry{},
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
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t, fakedatastore.New(t))
			defer test.Cleanup()

			test.withCallerID = !tt.failCallerID
			test.ef.entries = tt.fetcherEntries
			test.ef.err = tt.fetcherErr
			resp, err := test.client.GetAuthorizedEntries(ctx, &entrypb.GetAuthorizedEntriesRequest{
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
			expectResponse := &entrypb.GetAuthorizedEntriesResponse{
				Entries: tt.expectEntries,
			}
			spiretest.AssertProtoEqual(t, expectResponse, resp)
		})
	}
}

func createFederatedBundles(t *testing.T, ds datastore.DataStore) {
	_, err := ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
		Bundle: &common.Bundle{
			TrustDomainId: federatedTd.IDString(),
			RootCas: []*common.Certificate{
				{
					DerBytes: []byte("federated bundle"),
				},
			},
		},
	})
	require.NoError(t, err)
	_, err = ds.CreateBundle(ctx, &datastore.CreateBundleRequest{
		Bundle: &common.Bundle{
			TrustDomainId: secondFederatedTd.IDString(),
			RootCas: []*common.Certificate{
				{
					DerBytes: []byte("second federated bundle"),
				},
			},
		},
	})
	require.NoError(t, err)
}

func createTestEntries(t *testing.T, ds datastore.DataStore, entry ...*common.RegistrationEntry) map[string]*common.RegistrationEntry {
	entriesMap := make(map[string]*common.RegistrationEntry)

	for _, e := range entry {
		resp, err := ds.CreateRegistrationEntry(ctx, &datastore.CreateRegistrationEntryRequest{
			Entry: e,
		})
		require.NoError(t, err)

		entriesMap[resp.Entry.SpiffeId] = resp.Entry
	}

	return entriesMap
}

type serviceTest struct {
	client       entrypb.EntryClient
	ef           *entryFetcher
	done         func()
	ds           datastore.DataStore
	logHook      *test.Hook
	withCallerID bool
}

func (s *serviceTest) Cleanup() {
	s.done()
}

func setupServiceTest(t *testing.T, ds datastore.DataStore) *serviceTest {
	ef := &entryFetcher{}
	service := entry.New(entry.Config{
		TrustDomain:  td,
		DataStore:    ds,
		EntryFetcher: ef,
	})

	log, logHook := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		entry.RegisterService(s, service)
	}

	test := &serviceTest{
		ds:      ds,
		logHook: logHook,
		ef:      ef,
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		if test.withCallerID {
			ctx = rpccontext.WithCallerID(ctx, agentID)
		}
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)
	test.done = done
	test.client = entrypb.NewEntryClient(conn)

	return test
}

func TestBatchUpdateEntry(t *testing.T) {
	parent := &types.SPIFFEID{TrustDomain: "example.org", Path: "/parent"}
	entry1SpiffeID := &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"}
	expiresAt := time.Now().Unix()
	initialEntry := &types.Entry{
		ParentId: parent,
		SpiffeId: entry1SpiffeID,
		Ttl:      60,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "uid:2000"},
		},
		FederatesWith: []string{
			federatedTd.String(),
		},
		Admin:      true,
		ExpiresAt:  expiresAt,
		DnsNames:   []string{"dns1", "dns2"},
		Downstream: true,
	}
	updateEverythingEntry := &types.Entry{
		ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/validUpdated"},
		SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/validUpdated"},
		Ttl:      500000,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:9999"},
		},
		FederatesWith: []string{},
		Admin:         false,
		ExpiresAt:     999999999,
		DnsNames:      []string{"dns3", "dns4"},
		Downstream:    false,
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
		expectResults   []*entrypb.BatchUpdateEntryResponse_Result
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/parentUpdated"}},
				},
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workloadUpdated"}},
				},
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
				// In the next test, we test multiple seletors, and just don't verify against the data
				// store
				modifiedEntry.Selectors = []*types.Selector{
					{Type: "unix", Value: "uid:2000"},
				}
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Selectors: []*types.Selector{
							{Type: "unix", Value: "uid:2000"},
						},
					},
				},
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
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
		},
		{
			name:           "Success Update TTL",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				Ttl: true,
			},
			outputMask: &types.EntryMask{
				Ttl: true,
			},
			updateEntries: []*types.Entry{
				{
					Ttl: 1000,
				},
			},
			expectDsEntries: func(id string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = id
				modifiedEntry.Ttl = 1000
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Ttl: 1000,
					},
				},
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						FederatesWith: []string{},
					},
				},
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Admin: false,
					},
				},
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Downstream: false,
					},
				},
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						ExpiresAt: 999,
					},
				},
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						DnsNames: []string{"dnsUpdated"},
					},
				},
			},
		},
		{
			name:           "Success Don't Update TTL",
			initialEntries: []*types.Entry{initialEntry},
			inputMask:      &types.EntryMask{
				// With this empty, the update operation should be a no-op
			},
			outputMask: &types.EntryMask{
				Ttl: true,
			},
			updateEntries: []*types.Entry{
				{
					Ttl: 500000,
				},
			},
			expectDsEntries: func(m string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = m
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						Ttl: 60,
					},
				},
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.InvalidArgument),
						Message: "failed to convert entry: invalid spiffe ID: trust domain is empty"},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: failed to convert entry",
						Data: logrus.Fields{
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							logrus.ErrorKey:          "invalid spiffe ID: trust domain is empty",
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.InvalidArgument),
						Message: "failed to convert entry: invalid parent ID: trust domain is empty"},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: failed to convert entry",
						Data: logrus.Fields{
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
							logrus.ErrorKey:          "invalid parent ID: trust domain is empty",
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.InvalidArgument),
						Message: "failed to convert entry: invalid parent ID: trust domain is empty"},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: failed to convert entry",
						Data: logrus.Fields{
							"error":                  "invalid parent ID: trust domain is empty",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.InvalidArgument),
						Message: "failed to convert entry: invalid spiffe ID: trust domain is empty"},
				},
			},
			expectLogs: func(m map[string]string) []spiretest.LogEntry {
				return []spiretest.LogEntry{
					{
						Level:   logrus.ErrorLevel,
						Message: "Invalid argument: failed to convert entry",
						Data: logrus.Fields{
							"error":                  "invalid spiffe ID: trust domain is empty",
							telemetry.RegistrationID: m[entry1SpiffeID.Path],
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.InvalidArgument),
						Message: "failed to convert entry: selector list is empty"},
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/validUpdated"},
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/validUpdated"},
						Ttl:      500000,
						Selectors: []*types.Selector{
							{Type: "unix", Value: "uid:9999"},
						},
						FederatesWith:  []string{},
						Admin:          false,
						ExpiresAt:      999999999,
						DnsNames:       []string{"dns3", "dns4"},
						Downstream:     false,
						RevisionNumber: 1,
					},
				},
			},
		},
		{
			name:           "Success Nil Output Mask",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				Ttl: true,
			},
			outputMask: nil,
			updateEntries: []*types.Entry{
				{
					Ttl: 500000,
				},
			},
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						ParentId: parent,
						SpiffeId: entry1SpiffeID,
						Ttl:      500000,
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
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry: &types.Entry{
						SpiffeId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
					},
				},
			},
		},
		{
			name:           "Success Empty Output Mask",
			initialEntries: []*types.Entry{initialEntry},
			inputMask: &types.EntryMask{
				Ttl: true,
			},
			// With the output mask empty, the update will take place, but the results will be empty
			outputMask: &types.EntryMask{},
			updateEntries: []*types.Entry{
				{
					Ttl: 500000,
				},
			},
			expectDsEntries: func(m string) []*types.Entry {
				modifiedEntry := proto.Clone(initialEntry).(*types.Entry)
				modifiedEntry.Id = m
				modifiedEntry.Ttl = 500000
				modifiedEntry.RevisionNumber = 1
				return []*types.Entry{modifiedEntry}
			},
			expectResults: []*entrypb.BatchUpdateEntryResponse_Result{
				{
					Status: &types.Status{Code: int32(codes.OK), Message: "OK"},
					Entry:  &types.Entry{},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ds := fakedatastore.New(t)
			test := setupServiceTest(t, ds)
			defer test.Cleanup()
			// Create fedeated bundles, that we use on "FederatesWith"
			createFederatedBundles(t, test.ds)

			// First create the initial entries
			createResp, err := test.client.BatchCreateEntry(ctx, &entrypb.BatchCreateEntryRequest{
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

			// Actually do the update, with the proper IDs
			resp, err := test.client.BatchUpdateEntry(ctx, &entrypb.BatchUpdateEntryRequest{
				Entries:    updateEntries,
				InputMask:  tt.inputMask,
				OutputMask: tt.outputMask,
			})
			require.NoError(t, err)

			if tt.expectLogs != nil {
				spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs(spiffeToIDMap))
			}
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
				}
			}

			spiretest.AssertProtoEqual(t, &entrypb.BatchUpdateEntryResponse{
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
				spiretest.AssertProtoEqual(t, firstEntry, tt.expectDsEntries(listEntries.Entries[0].EntryId)[0])
			}
		})
	}
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

func (f *fakeDS) CreateRegistrationEntry(ctx context.Context, req *datastore.CreateRegistrationEntryRequest) (*datastore.CreateRegistrationEntryResponse, error) {
	if !f.customCreate {
		return f.DataStore.CreateRegistrationEntry(ctx, req)
	}

	if f.err != nil {
		return nil, f.err
	}
	entryID := req.Entry.EntryId

	expect, ok := f.expectEntries[entryID]
	assert.True(f.t, ok, "no expect entry found")

	// Validate we get expected entry
	spiretest.AssertProtoEqual(f.t, expect, req.Entry)

	// Return expect when no custom result configured
	if len(f.results) == 0 {
		return &datastore.CreateRegistrationEntryResponse{
			Entry: expect,
		}, nil
	}

	res, ok := f.results[entryID]
	assert.True(f.t, ok, "no result found")

	return &datastore.CreateRegistrationEntryResponse{
		Entry: res,
	}, nil
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
