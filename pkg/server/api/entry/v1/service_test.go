package entry_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/entry/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	entrypb "github.com/spiffe/spire/proto/spire-next/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ctx         = context.Background()
	td          = spiffeid.RequireTrustDomainFromString("example.org")
	federatedTd = spiffeid.RequireTrustDomainFromString("domain1.org")
	agentID     = spiffeid.RequireFromString("spiffe://example.org/agent")
)

func TestListEntries(t *testing.T) {
	parentID := td.NewID("parent")
	childID := td.NewID("child")
	secondChildID := td.NewID("second_child")

	protoParentID := api.ProtoFromID(parentID)
	protoChildID := api.ProtoFromID(childID)
	protoSecondChildID := api.ProtoFromID(secondChildID)
	badID := &types.SPIFFEID{
		TrustDomain: "http://example.org",
		Path:        "/bad",
	}

	childRegEntry := &common.RegistrationEntry{
		ParentId: parentID.String(),
		SpiffeId: childID.String(),
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:1000"},
			{Type: "unix", Value: "gid:1000"},
		},
	}
	secondChildRegEntry := &common.RegistrationEntry{
		ParentId: parentID.String(),
		SpiffeId: secondChildID.String(),
		Selectors: []*common.Selector{
			{Type: "unix", Value: "uid:1000"},
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
	}

	expectedSecondChild := &types.Entry{
		Id:       secondChildEntry.Entry.EntryId,
		ParentId: protoParentID,
		SpiffeId: protoSecondChildID,
		Selectors: []*types.Selector{
			{Type: "unix", Value: "uid:1000"},
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
			name:            "ByParentId",
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByParentId: protoParentID,
				},
			},
		},
		{
			name:            "BySpiffeId",
			expectedEntries: []*types.Entry{expectedChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					BySpiffeId: protoChildID,
				},
			},
		},
		{
			name:            "BySelectors with SelectorMatch_MATCH_EXACT",
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
			name:            "BySelectors with SelectorMatch_MATCH_SUBSET",
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
			name:                  "PageSize",
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
			name:   "bad ByParentId",
			err:    "invalid request: malformed ByParentId: spiffeid: invalid scheme",
			code:   codes.InvalidArgument,
			logMsg: "Invalid request",
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					ByParentId: badID,
				},
			},
		},
		{
			name:   "bad BySpiffeId",
			err:    "invalid request: malformed BySpiffeId: spiffeid: invalid scheme",
			code:   codes.InvalidArgument,
			logMsg: "Invalid request",
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					BySpiffeId: badID,
				},
			},
		},
		{
			name:            "bad BySelectors (no selectors)",
			err:             "invalid request: malformed BySelectors: empty selector set",
			code:            codes.InvalidArgument,
			expectedEntries: []*types.Entry{expectedChild, expectedSecondChild},
			request: &entrypb.ListEntriesRequest{
				Filter: &entrypb.ListEntriesRequest_Filter{
					BySelectors: &types.SelectorMatch{},
				},
			},
		},
		{
			name:   "bad BySelectors (bad selector)",
			err:    "invalid request: malformed BySelectors: missing selector type",
			code:   codes.InvalidArgument,
			logMsg: "Invalid request",
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
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ds.SetNextError(tt.dsError)

			// exercise
			entries, err := test.client.ListEntries(context.Background(), tt.request)

			// assert
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
			if tt.logMsg != "" {
				require.Contains(t, test.logHook.LastEntry().Message, tt.logMsg)
			}
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
				FederatesWith: []string{federatedTd.IDString()},
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
					Message: "Invalid request: missing ID",
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
			err:     "failed to convert entry: spiffeid: invalid scheme",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to convert entry",
					Data: logrus.Fields{
						telemetry.RegistrationID: malformedEntry.Entry.EntryId,
						logrus.ErrorKey:          "spiffeid: invalid scheme",
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
					Message: "Invalid request: failed to convert entry",
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
						FederatesWith: []string{"spiffe://domain1.org"},
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
			name: "fails creating similar entry",
			expectResults: []*entrypb.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.AlreadyExists),
						Message: "entry already exists",
					},
				},
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
						Message: "failed to convert entry: invalid parent ID: spiffeid: trust domain is empty",
					},
				},
			},
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid request: failed to convert entry",
					Data: logrus.Fields{
						logrus.ErrorKey: "invalid parent ID: spiffeid: trust domain is empty",
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
					Message: "Unable to convert registration entry",
					Data: logrus.Fields{
						logrus.ErrorKey:    "spiffeid: invalid scheme",
						telemetry.SPIFFEID: "spiffe://example.org/workload",
					},
				},
			},
			expectResults: []*entrypb.BatchCreateEntryResponse_Result{
				{
					Status: &types.Status{
						Code:    int32(codes.Internal),
						Message: "unable to convert registration entry: spiffeid: invalid scheme",
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

			// Create fedeated bundles, that we use on "FederatesWith"
			createFederatedBundles(t, ds)
			_ = createTestEntries(t, ds, defaultEntry)

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

				return results, nil
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
							Message: "Invalid request: missing entry ID",
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
				}, nil
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
			"spiffe://domain1.com",
			"spiffe://domain2.com",
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
			"spiffe://domain3.com",
			"spiffe://domain4.com",
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
			err:        "failed to fetch registration entries",
			code:       codes.Internal,
			fetcherErr: "fetcher fails",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to fetch registration entries",
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
