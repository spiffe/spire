package entry_test

import (
	"context"
	"errors"
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
	entrypb "github.com/spiffe/spire/proto/spire-next/api/server/entry/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var (
	ctx         = context.Background()
	td          = spiffeid.RequireTrustDomainFromString("example.org")
	federatedTd = spiffeid.RequireTrustDomainFromString("domain1.org")
)

func TestGetEntry(t *testing.T) {
	ds := fakedatastore.New()
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
			ds.SetError(tt.dsError)

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

func TestBatchDeleteEntry(t *testing.T) {
	expiresAt := time.Now().Unix()
	parentID := td.NewID("host").String()

	fooSpiffeID := td.NewID("foo").String()
	fooEntry := &common.RegistrationEntry{
		ParentId:    parentID,
		SpiffeId:    fooSpiffeID,
		EntryExpiry: expiresAt,
	}
	barSpiffeID := td.NewID("bar").String()
	barEntry := &common.RegistrationEntry{
		ParentId:    parentID,
		SpiffeId:    barSpiffeID,
		EntryExpiry: expiresAt,
	}
	bazSpiffeID := td.NewID("baz").String()
	baz := &common.RegistrationEntry{
		ParentId:    parentID,
		SpiffeId:    bazSpiffeID,
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
						Message: "no such registration entry",
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
							Message: "no such registration entry",
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
			ds := fakedatastore.New()
			ds.SetError(tt.dsError)
			test := setupServiceTest(t, ds)
			defer test.Cleanup()

			// Create entries
			entriesMap := createTestEntries(t, ds, fooEntry, barEntry, baz)

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
	client  entrypb.EntryClient
	done    func()
	ds      datastore.DataStore
	logHook *test.Hook
}

func (s *serviceTest) Cleanup() {
	s.done()
}

func setupServiceTest(t *testing.T, ds datastore.DataStore) *serviceTest {
	service := entry.New(entry.Config{
		Datastore: ds,
	})

	log, logHook := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		entry.RegisterService(s, service)
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
	test.client = entrypb.NewEntryClient(conn)

	return test
}
