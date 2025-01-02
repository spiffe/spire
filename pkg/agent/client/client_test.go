package client

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api/entry/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/testing/protocmp"
)

var (
	ctx = context.Background()

	log, logHook = test.NewNullLogger()

	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")

	testEntries = []*common.RegistrationEntry{
		{
			EntryId:  "ENTRYID1",
			SpiffeId: "spiffe://example.org/id1",
			Selectors: []*common.Selector{
				{Type: "S", Value: "1"},
			},
			FederatesWith: []string{
				"spiffe://domain1.test",
			},
			RevisionNumber: 1234,
			Hint:           "external",
		},
		// This entry should be ignored since it is missing an entry ID
		{
			SpiffeId: "spiffe://example.org/id2",
			Selectors: []*common.Selector{
				{Type: "S", Value: "2"},
			},
			FederatesWith: []string{
				"spiffe://domain2.test",
			},
		},
		// This entry should be ignored since it is missing a SPIFFE ID
		{
			EntryId: "ENTRYID3",
			Selectors: []*common.Selector{
				{Type: "S", Value: "3"},
			},
		},
		// This entry should be ignored since it is missing selectors
		{
			EntryId:  "ENTRYID4",
			SpiffeId: "spiffe://example.org/id4",
		},
	}

	testSvids = map[string]*X509SVID{
		"entry-id": {
			CertChain: []byte{11, 22, 33},
		},
	}

	testBundles = map[string]*common.Bundle{
		"spiffe://example.org": {
			TrustDomainId: "spiffe://example.org",
			RootCas: []*common.Certificate{
				{DerBytes: []byte{10, 20, 30, 40}},
			},
		},
		"spiffe://domain1.test": {
			TrustDomainId: "spiffe://domain1.test",
			RootCas: []*common.Certificate{
				{DerBytes: []byte{10, 20, 30, 40}},
			},
		},
	}
)

func TestFetchUpdates(t *testing.T) {
	client, tc := createClient(t)

	tc.entryServer.entries = []*types.Entry{
		{
			Id:       "ENTRYID1",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id1",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "1"},
			},
			FederatesWith:  []string{"domain1.test"},
			RevisionNumber: 1234,
			Hint:           "external",
		},
		// This entry should be ignored since it is missing an entry ID
		{
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id2",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "2"},
			},
			FederatesWith: []string{"domain2.test"},
		},
		// This entry should be ignored since it is missing a SPIFFE ID
		{
			Id:       "ENTRYID3",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			Selectors: []*types.Selector{
				{Type: "S", Value: "3"},
			},
		},
		// This entry should be ignored since it is missing selectors
		{
			Id:       "ENTRYID4",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id4",
			},
		},
	}

	tc.svidServer.x509SVIDs = map[string]*types.X509SVID{
		"entry-id": {
			Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
			CertChain: [][]byte{{11, 22, 33}},
		},
	}

	tc.bundleServer.serverBundle = makeAPIBundle("example.org")
	tc.bundleServer.federatedBundles = map[string]*types.Bundle{
		"domain1.test": makeAPIBundle("domain1.test"),
		"domain2.test": makeAPIBundle("domain2.test"),
	}

	// Simulate an ongoing SVID rotation (request should not be made in the middle of a rotation)
	client.c.RotMtx.Lock()

	// Do the request in a different go routine
	var wg sync.WaitGroup
	var update *Update
	err := errors.New("a not nil error")
	wg.Add(1)
	go func() {
		defer wg.Done()
		update, err = client.FetchUpdates(ctx)
	}()

	// The request should wait until the SVID rotation finishes
	require.Contains(t, "a not nil error", err.Error())
	require.Nil(t, update)

	// Simulate the end of the SVID rotation
	client.c.RotMtx.Unlock()
	wg.Wait()

	// Assert results
	require.Nil(t, err)
	assert.Equal(t, testBundles, update.Bundles)
	// Only the first registration entry should be returned since the rest are
	// invalid for one reason or another
	if assert.Len(t, update.Entries, 1) {
		entry := testEntries[0]
		assert.Equal(t, entry, update.Entries[entry.EntryId])
	}
	assertConnectionIsNotNil(t, client)
}

func TestSyncUpdatesBundles(t *testing.T) {
	client, tc := createClient(t)

	tc.bundleServer.serverBundle = makeAPIBundle("example.org")

	cachedEntries := make(map[string]*common.RegistrationEntry)
	cachedBundles := make(map[string]*common.Bundle)

	syncUpdates := func() {
		stats, err := client.SyncUpdates(ctx, cachedEntries, cachedBundles)
		require.NoError(t, err)
		assert.Equal(t, SyncBundlesStats{Total: len(cachedBundles)}, stats.Bundles)
	}

	// Assert that the server bundle is synced. No other bundles are expected
	// since no entries are configured to federate.
	syncUpdates()
	assert.Equal(t, map[string]*common.Bundle{
		"spiffe://example.org": makeCommonBundle("example.org"),
	}, cachedBundles)

	// Add in new federated bundles that should not yet be synced because there
	// is no entry that federates with them.
	tc.bundleServer.federatedBundles = map[string]*types.Bundle{
		"domain1.test": makeAPIBundle("domain1.test"),
		"domain2.test": makeAPIBundle("domain2.test"),
	}
	tc.entryServer.entries = []*types.Entry{
		{
			Id:        "0",
			SpiffeId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
			ParentId:  &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
			Selectors: []*types.Selector{{Type: "not", Value: "relevant"}},
		},
	}

	syncUpdates()
	assert.Len(t, cachedEntries, 1)
	assert.Equal(t, map[string]*common.Bundle{
		"spiffe://example.org": makeCommonBundle("example.org"),
	}, cachedBundles)

	// Change the entry to federate and assert the federated bundle is synced.
	tc.entryServer.entries[0].RevisionNumber++
	tc.entryServer.entries[0].FederatesWith = []string{"domain1.test"}
	syncUpdates()
	assert.Equal(t, map[string]*common.Bundle{
		"spiffe://example.org":  makeCommonBundle("example.org"),
		"spiffe://domain1.test": makeCommonBundle("domain1.test"),
	}, cachedBundles)

	// Change the entry to federate with a different bundle and assert the new
	// federated bundle is synced and the old is removed.
	tc.entryServer.entries[0].RevisionNumber++
	tc.entryServer.entries[0].FederatesWith = []string{"domain2.test"}
	syncUpdates()
	assert.Equal(t, map[string]*common.Bundle{
		"spiffe://example.org":  makeCommonBundle("example.org"),
		"spiffe://domain2.test": makeCommonBundle("domain2.test"),
	}, cachedBundles)
}

func TestSyncUpdatesEntries(t *testing.T) {
	client, tc := createClient(t)

	tc.bundleServer.serverBundle = makeAPIBundle("example.org")

	cachedBundles := make(map[string]*common.Bundle)
	cachedEntries := make(map[string]*common.RegistrationEntry)

	syncAndAssertEntries := func(t *testing.T, total, missing, stale, dropped int, expectedEntries ...*types.Entry) {
		t.Helper()
		expected := make(map[string]*common.RegistrationEntry)
		for _, entry := range expectedEntries {
			commonEntry, err := slicedEntryFromProto(entry)
			require.NoError(t, err)
			expected[entry.Id] = commonEntry
		}
		tc.entryServer.SetEntries(expectedEntries...)
		stats, err := client.SyncUpdates(ctx, cachedEntries, cachedBundles)
		require.NoError(t, err)
		assert.Equal(t, SyncEntriesStats{
			Total:   total,
			Missing: missing,
			Stale:   stale,
			Dropped: dropped,
		}, stats.Entries)
		assert.Equal(t, expected, cachedEntries)
	}

	entryA1 := makeEntry("A", 1)
	entryB1 := makeEntry("B", 1)
	entryC1 := makeEntry("C", 1)
	entryD1 := makeEntry("D", 1)

	entryA2 := makeEntry("A", 2)
	entryB2 := makeEntry("B", 2)
	entryC2 := makeEntry("C", 2)

	// No entries yet
	syncAndAssertEntries(t, 0, 0, 0, 0)

	// Partial page to test entries in first response are processed ok.
	syncAndAssertEntries(t, 1, 1, 0, 0, entryA1)

	// Single page to test entries in first response are processed ok.
	syncAndAssertEntries(t, 2, 1, 0, 0, entryA1, entryB1)

	// More than one page to test entry revision based diff
	syncAndAssertEntries(t, 3, 1, 0, 0, entryA1, entryB1, entryC1)

	// More than one page to test entry revision based diff
	syncAndAssertEntries(t, 4, 1, 0, 0, entryA1, entryB1, entryC1, entryD1)

	// Sync down new A, B, and C entries and drop D.
	syncAndAssertEntries(t, 3, 0, 3, 1, entryA2, entryB2, entryC2)

	// Sync again but with no changes.
	syncAndAssertEntries(t, 3, 0, 0, 0, entryA2, entryB2, entryC2)
}

func TestRenewSVID(t *testing.T) {
	client, tc := createClient(t)

	for _, tt := range []struct {
		name       string
		agentErr   error
		err        string
		expectSVID *X509SVID
		csr        []byte
		agentSVID  *types.X509SVID
		expectLogs []spiretest.LogEntry
	}{
		{
			name: "success",
			csr:  []byte{0, 1, 2},
			agentSVID: &types.X509SVID{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "/agent1",
				},
				CertChain: [][]byte{{1, 2, 3}},
				ExpiresAt: 12345,
			},
			expectSVID: &X509SVID{
				CertChain: []byte{1, 2, 3},
				ExpiresAt: 12345,
			},
		},
		{
			name: "no csr",
			csr:  []byte(nil),
			agentSVID: &types.X509SVID{
				Id: &types.SPIFFEID{
					TrustDomain: "example.org",
					Path:        "/agent1",
				},
				CertChain: [][]byte{{1, 2, 3}},
				ExpiresAt: 12345,
			},
			err: "failed to renew agent: rpc error: code = Unknown desc = malformed param",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to renew agent",
					Data: logrus.Fields{
						telemetry.StatusCode:    "Unknown",
						telemetry.StatusMessage: "malformed param",
						telemetry.Error:         "rpc error: code = Unknown desc = malformed param",
					},
				},
			},
		},
		{
			name:     "renew agent fails",
			csr:      []byte{0, 1, 2},
			agentErr: errors.New("renew fails"),
			err:      "failed to renew agent: rpc error: code = Unknown desc = renew fails",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to renew agent",
					Data: logrus.Fields{
						telemetry.StatusCode:    "Unknown",
						telemetry.StatusMessage: "renew fails",
						telemetry.Error:         "rpc error: code = Unknown desc = renew fails",
					},
				},
			},
		},
		{
			name:     "call to RenewAgent fails",
			csr:      []byte{0, 1, 2},
			agentErr: status.Error(codes.Internal, "renew fails"),
			err:      "failed to renew agent: rpc error: code = Internal desc = renew fails",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to renew agent",
					Data: logrus.Fields{
						telemetry.StatusCode:    "Internal",
						telemetry.StatusMessage: "renew fails",
						telemetry.Error:         "rpc error: code = Internal desc = renew fails",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			logHook.Reset()
			tc.agentServer.err = tt.agentErr
			tc.agentServer.svid = tt.agentSVID

			svid, err := client.RenewSVID(ctx, tt.csr)
			spiretest.AssertLogs(t, logHook.AllEntries(), tt.expectLogs)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				require.Nil(t, svid)
				return
			}

			require.Nil(t, err)
			require.Equal(t, tt.expectSVID, svid)

			assertConnectionIsNotNil(t, client)
		})
	}
}

func TestNewX509SVIDs(t *testing.T) {
	sClient, tc := createClient(t)
	entries := []*types.Entry{
		{
			Id:       "ENTRYID1",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id1",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "1"},
			},
			FederatesWith:  []string{"domain1.test"},
			RevisionNumber: 1234,
		},
		// This entry should be ignored since it is missing an entry ID
		{
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id2",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "2"},
			},
			FederatesWith: []string{"domain2.test"},
		},
		// This entry should be ignored since it is missing a SPIFFE ID
		{
			Id:       "ENTRYID3",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			Selectors: []*types.Selector{
				{Type: "S", Value: "3"},
			},
		},
		// This entry should be ignored since it is missing selectors
		{
			Id:       "ENTRYID4",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id4",
			},
		},
	}
	x509SVIDs := map[string]*types.X509SVID{
		"entry-id": {
			Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
			CertChain: [][]byte{{11, 22, 33}},
		},
	}

	tests := []struct {
		name           string
		entries        []*types.Entry
		x509SVIDs      map[string]*types.X509SVID
		batchSVIDErr   error
		wantError      assert.ErrorAssertionFunc
		assertFuncConn func(t *testing.T, client *client)
		testSvids      map[string]*X509SVID
		expectedLogs   []spiretest.LogEntry
	}{
		{
			name:           "success",
			entries:        entries,
			x509SVIDs:      x509SVIDs,
			batchSVIDErr:   nil,
			wantError:      assert.NoError,
			assertFuncConn: assertConnectionIsNotNil,
			testSvids:      testSvids,
		},
		{
			name:           "failed",
			entries:        entries,
			x509SVIDs:      x509SVIDs,
			batchSVIDErr:   status.Error(codes.NotFound, "not found when executing BatchNewX509SVID"),
			wantError:      assert.Error,
			assertFuncConn: assertConnectionIsNil,
			testSvids:      nil,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to batch new X509 SVID(s)",
					Data: logrus.Fields{
						telemetry.StatusCode:    "NotFound",
						telemetry.StatusMessage: "not found when executing BatchNewX509SVID",
						logrus.ErrorKey:         "rpc error: code = NotFound desc = not found when executing BatchNewX509SVID",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc.entryServer.entries = tt.entries
			tc.svidServer.x509SVIDs = tt.x509SVIDs
			tc.svidServer.batchSVIDErr = tt.batchSVIDErr

			// Simulate an ongoing SVID rotation (request should not be made in the middle of a rotation)
			sClient.c.RotMtx.Lock()

			// Do the request in a different go routine
			var wg sync.WaitGroup
			var svids map[string]*X509SVID
			err := errors.New("a not nil error")
			wg.Add(1)
			go func() {
				defer wg.Done()
				svids, err = sClient.NewX509SVIDs(ctx, newTestCSRs())
			}()

			// The request should wait until the SVID rotation finishes
			require.Contains(t, "a not nil error", err.Error())
			require.Nil(t, svids)

			// Simulate the end of the SVID rotation
			sClient.c.RotMtx.Unlock()
			wg.Wait()

			// Assert results
			spiretest.AssertLogsContainEntries(t, logHook.AllEntries(), tt.expectedLogs)
			tt.assertFuncConn(t, sClient)
			if !tt.wantError(t, err, fmt.Sprintf("error was not expected for test case %s", tt.name)) {
				return
			}
			assert.Equal(t, tt.testSvids, svids)
		})
	}
}

func newTestCSRs() map[string][]byte {
	return map[string][]byte{
		"entry-id": {1, 2, 3, 4},
	}
}

func TestFetchReleaseWaitsForFetchUpdatesToFinish(t *testing.T) {
	client, tc := createClient(t)

	tc.entryServer.entries = []*types.Entry{
		{
			Id:       "ENTRYID1",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id1",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "1"},
			},
			FederatesWith:  []string{"domain1.test"},
			RevisionNumber: 1234,
			Hint:           "external",
		},
		// This entry should be ignored since it is missing an entry ID
		{
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id2",
			},
			Selectors: []*types.Selector{
				{Type: "S", Value: "2"},
			},
			FederatesWith: []string{"domain2.test"},
		},
		// This entry should be ignored since it is missing a SPIFFE ID
		{
			Id:       "ENTRYID3",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			Selectors: []*types.Selector{
				{Type: "S", Value: "3"},
			},
		},
		// This entry should be ignored since it is missing selectors
		{
			Id:       "ENTRYID4",
			ParentId: &types.SPIFFEID{TrustDomain: "example.org", Path: "/host"},
			SpiffeId: &types.SPIFFEID{
				TrustDomain: "example.org",
				Path:        "/id4",
			},
		},
	}

	tc.svidServer.x509SVIDs = map[string]*types.X509SVID{
		"entry-id": {
			Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
			CertChain: [][]byte{{11, 22, 33}},
		},
	}

	waitForRelease := make(chan struct{})
	tc.bundleServer.simulateRelease = func() {
		client.Release()
		close(waitForRelease)
	}

	tc.bundleServer.serverBundle = &types.Bundle{
		TrustDomain:     "example.org",
		X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
	}
	tc.bundleServer.federatedBundles = map[string]*types.Bundle{
		"domain1.test": {
			TrustDomain:     "domain1.test",
			X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
		},
		"domain2.test": {
			TrustDomain:     "domain2.test",
			X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
		},
	}

	update, err := client.FetchUpdates(ctx)
	require.NoError(t, err)

	assert.Equal(t, testBundles, update.Bundles)
	// Only the first registration entry should be returned since the rest are
	// invalid for one reason or another
	if assert.Len(t, update.Entries, 1) {
		entry := testEntries[0]
		assert.Equal(t, entry, update.Entries[entry.EntryId])
	}
	select {
	case <-waitForRelease:
	case <-time.After(time.Second * 5):
		require.FailNow(t, "timed out waiting for release")
	}
	assertConnectionIsNil(t, client)
}

func TestNewNodeClientRelease(t *testing.T) {
	client, _ := createClient(t)

	for range 3 {
		// Create agent client and release
		_, r, err := client.newAgentClient(ctx)
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Create bundle client and release
		_, r, err = client.newBundleClient(ctx)
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Create entry client and release
		_, r, err = client.newEntryClient(ctx)
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Create svid client and release
		_, r, err = client.newSVIDClient(ctx)
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Release client
		client.Release()
		assertConnectionIsNil(t, client)
		// test that release is idempotent
		client.Release()
		assertConnectionIsNil(t, client)
	}
}

func TestNewNodeInternalClientRelease(t *testing.T) {
	client, _ := createClient(t)

	for range 3 {
		// Create agent client
		_, conn, err := client.newAgentClient(ctx)
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)

		// Create bundle client
		_, conn, err = client.newBundleClient(ctx)
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)

		// Create entry client
		_, conn, err = client.newEntryClient(ctx)
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)

		// Create svid client
		_, conn, err = client.newSVIDClient(ctx)
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)
	}
}

func TestFetchUpdatesReleaseConnectionIfItFailsToFetch(t *testing.T) {
	for _, tt := range []struct {
		name      string
		err       string
		setupTest func(tc *testServer)
	}{
		{
			name: "Entries",
			setupTest: func(tc *testServer) {
				tc.entryServer.err = errors.New("an error")
			},
			err: "failed to fetch authorized entries: rpc error: code = Unknown desc = an error",
		},
		{
			name: "Agent bundle",
			setupTest: func(tc *testServer) {
				tc.bundleServer.bundleErr = errors.New("an error")
			},
			err: "failed to fetch bundle: rpc error: code = Unknown desc = an error",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client, tc := createClient(t)
			tt.setupTest(tc)

			update, err := client.FetchUpdates(ctx)
			assert.Nil(t, update)
			assert.EqualError(t, err, tt.err)
			assertConnectionIsNil(t, client)
		})
	}
}

func TestFetchUpdatesReleaseConnectionIfItFails(t *testing.T) {
	client, tc := createClient(t)

	tc.entryServer.err = errors.New("an error")

	update, err := client.FetchUpdates(ctx)
	assert.Nil(t, update)
	assert.Error(t, err)
	assertConnectionIsNil(t, client)
}

func TestFetchUpdatesAddStructuredLoggingIfCallToFetchEntriesFails(t *testing.T) {
	logHook.Reset()
	client, tc := createClient(t)

	tc.entryServer.err = status.Error(codes.Internal, "call to grpc method fetchEntries has failed")
	update, err := client.FetchUpdates(ctx)
	assert.Nil(t, update)
	assert.Error(t, err)
	assertConnectionIsNil(t, client)

	var entries []spiretest.LogEntry
	entries = append(entries, spiretest.LogEntry{
		Level:   logrus.ErrorLevel,
		Message: "Failed to fetch authorized entries",
		Data: logrus.Fields{
			telemetry.StatusCode:    "Internal",
			telemetry.StatusMessage: "call to grpc method fetchEntries has failed",
			telemetry.Error:         tc.entryServer.err.Error(),
		},
	})

	spiretest.AssertLogs(t, logHook.AllEntries(), entries)
}

func TestFetchUpdatesAddStructuredLoggingIfCallToFetchBundlesFails(t *testing.T) {
	logHook.Reset()
	client, tc := createClient(t)

	tc.bundleServer.bundleErr = status.Error(codes.Internal, "call to grpc method fetchBundles has failed")
	update, err := client.FetchUpdates(ctx)
	assert.Nil(t, update)
	assert.Error(t, err)
	assertConnectionIsNil(t, client)

	var entries []spiretest.LogEntry
	entries = append(entries, spiretest.LogEntry{
		Level:   logrus.ErrorLevel,
		Message: "Failed to fetch bundle",
		Data: logrus.Fields{
			telemetry.StatusCode:    "Internal",
			telemetry.StatusMessage: "call to grpc method fetchBundles has failed",
			telemetry.Error:         tc.bundleServer.bundleErr.Error(),
		},
	})

	spiretest.AssertLogs(t, logHook.AllEntries(), entries)
}

func TestNewAgentClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomain,
	})
	agentClient, conn, err := client.newAgentClient(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to dial")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestNewBundleClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomain,
	})
	agentClient, conn, err := client.newBundleClient(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to dial")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestNewEntryClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomain,
	})
	agentClient, conn, err := client.newEntryClient(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to dial")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestNewSVIDClientFailsDial(t *testing.T) {
	client := newClient(&Config{
		KeysAndBundle: keysAndBundle,
		TrustDomain:   trustDomain,
	})
	agentClient, conn, err := client.newSVIDClient(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to dial")
	require.Nil(t, agentClient)
	require.Nil(t, conn)
}

func TestFetchJWTSVID(t *testing.T) {
	client, tc := createClient(t)

	issuedAt := time.Now().Unix()
	expiresAt := time.Now().Add(time.Minute).Unix()
	for _, tt := range []struct {
		name       string
		setupTest  func(err error)
		err        string
		expectSVID *JWTSVID
		fetchErr   error
	}{
		{
			name: "success",
			setupTest: func(err error) {
				tc.svidServer.jwtSVID = &types.JWTSVID{
					Token:     "token",
					ExpiresAt: expiresAt,
					IssuedAt:  issuedAt,
				}
				tc.svidServer.newJWTSVID = err
			},
			expectSVID: &JWTSVID{
				Token:     "token",
				ExpiresAt: time.Unix(expiresAt, 0).UTC(),
				IssuedAt:  time.Unix(issuedAt, 0).UTC(),
			},
		},
		{
			name: "client fails",
			setupTest: func(err error) {
				tc.svidServer.newJWTSVID = err
			},
			err:      "failed to fetch JWT SVID: rpc error: code = Unknown desc = client fails",
			fetchErr: errors.New("client fails"),
		},
		{
			name: "empty response",
			setupTest: func(err error) {
				tc.svidServer.jwtSVID = nil
				tc.svidServer.newJWTSVID = err
			},
			err: "JWTSVID response missing SVID",
		},
		{
			name: "missing issuedAt",
			setupTest: func(err error) {
				tc.svidServer.jwtSVID = &types.JWTSVID{
					Token:     "token",
					ExpiresAt: expiresAt,
				}
				tc.svidServer.newJWTSVID = err
			},
			err: "JWTSVID missing issued at",
		},
		{
			name: "missing expiredAt",
			setupTest: func(err error) {
				tc.svidServer.jwtSVID = &types.JWTSVID{
					Token:    "token",
					IssuedAt: issuedAt,
				}
				tc.svidServer.newJWTSVID = err
			},
			err: "JWTSVID missing expires at",
		},
		{
			name: "issued after expired",
			setupTest: func(err error) {
				tc.svidServer.jwtSVID = &types.JWTSVID{
					Token:     "token",
					ExpiresAt: issuedAt,
					IssuedAt:  expiresAt,
				}
				tc.svidServer.newJWTSVID = err
			},
			err: "JWTSVID issued after it has expired",
		},
		{
			name: "grpc call to NewJWTSVID fails",
			setupTest: func(err error) {
				tc.svidServer.jwtSVID = &types.JWTSVID{
					Token:     "token",
					ExpiresAt: expiresAt,
					IssuedAt:  issuedAt,
				}
				tc.svidServer.newJWTSVID = err
			},
			err:      "failed to fetch JWT SVID: rpc error: code = Internal desc = NewJWTSVID fails",
			fetchErr: status.Error(codes.Internal, "NewJWTSVID fails"),
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			tt.setupTest(tt.fetchErr)
			resp, err := client.NewJWTSVID(ctx, "entry-id", []string{"myAud"})
			if tt.err != "" {
				require.Nil(t, resp)
				require.EqualError(t, err, tt.err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, tt.expectSVID, resp)
		})
	}
}

// createClient creates a sample client with mocked components for testing purposes
func createClient(t *testing.T) (*client, *testServer) {
	tc := &testServer{
		agentServer:  &fakeAgentServer{},
		bundleServer: &fakeBundleServer{},
		entryServer:  &fakeEntryServer{},
		svidServer:   &fakeSVIDServer{},
	}

	client := newClient(&Config{
		Addr:          "unix:///foo",
		Log:           log,
		KeysAndBundle: keysAndBundle,
		RotMtx:        new(sync.RWMutex),
		TrustDomain:   trustDomain,
	})

	server := grpc.NewServer()
	agentv1.RegisterAgentServer(server, tc.agentServer)
	bundlev1.RegisterBundleServer(server, tc.bundleServer)
	entryv1.RegisterEntryServer(server, tc.entryServer)
	svidv1.RegisterSVIDServer(server, tc.svidServer)

	listener := bufconn.Listen(1024)
	spiretest.ServeGRPCServerOnListener(t, server, listener)

	client.dialContext = func(ctx context.Context, addr string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
		return grpc.DialContext(ctx, addr, //nolint: staticcheck // It is going to be resolved on #5152
			grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}))
	}
	return client, tc
}

func keysAndBundle() ([]*x509.Certificate, crypto.Signer, []*x509.Certificate) {
	return nil, nil, nil
}

func assertConnectionIsNil(t *testing.T, client *client) {
	client.m.Lock()
	assert.Nil(t, client.connections, "Connection should be released")
	client.m.Unlock()
}

func assertConnectionIsNotNil(t *testing.T, client *client) {
	client.m.Lock()
	assert.NotNil(t, client.connections, "Connection should not be released")
	client.m.Unlock()
}

type fakeEntryServer struct {
	entryv1.UnimplementedEntryServer

	entries []*types.Entry
	err     error
}

func (c *fakeEntryServer) SetEntries(entries ...*types.Entry) {
	c.entries = entries
}

func (c *fakeEntryServer) GetAuthorizedEntries(_ context.Context, in *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
	if c.err != nil {
		return nil, c.err
	}

	if err := checkAuthorizedEntryOutputMask(in.OutputMask); err != nil {
		return nil, err
	}

	return &entryv1.GetAuthorizedEntriesResponse{
		Entries: c.entries,
	}, nil
}

func (c *fakeEntryServer) SyncAuthorizedEntries(stream entryv1.Entry_SyncAuthorizedEntriesServer) error {
	const entryPageSize = 2
	return entry.SyncAuthorizedEntries(stream, c.entries, entryPageSize)
}

type fakeBundleServer struct {
	bundlev1.UnimplementedBundleServer

	serverBundle       *types.Bundle
	federatedBundles   map[string]*types.Bundle
	bundleErr          error
	federatedBundleErr error

	simulateRelease func()
}

func (c *fakeBundleServer) GetBundle(context.Context, *bundlev1.GetBundleRequest) (*types.Bundle, error) {
	if c.bundleErr != nil {
		return nil, c.bundleErr
	}

	if c.simulateRelease != nil {
		go c.simulateRelease()
	}

	return c.serverBundle, nil
}

func (c *fakeBundleServer) GetFederatedBundle(_ context.Context, in *bundlev1.GetFederatedBundleRequest) (*types.Bundle, error) {
	if c.federatedBundleErr != nil {
		return nil, c.federatedBundleErr
	}
	b, ok := c.federatedBundles[in.TrustDomain]
	if !ok {
		return nil, errors.New("no federated bundle found")
	}

	return b, nil
}

type fakeSVIDServer struct {
	svidv1.UnimplementedSVIDServer

	batchSVIDErr    error
	newJWTSVID      error
	x509SVIDs       map[string]*types.X509SVID
	jwtSVID         *types.JWTSVID
	simulateRelease func()
}

func (c *fakeSVIDServer) BatchNewX509SVID(_ context.Context, in *svidv1.BatchNewX509SVIDRequest) (*svidv1.BatchNewX509SVIDResponse, error) {
	if c.batchSVIDErr != nil {
		return nil, c.batchSVIDErr
	}

	// Simulate async calls
	if c.simulateRelease != nil {
		go c.simulateRelease()
	}

	var results []*svidv1.BatchNewX509SVIDResponse_Result
	for _, param := range in.Params {
		svid, ok := c.x509SVIDs[param.EntryId]
		switch {
		case ok:
			results = append(results, &svidv1.BatchNewX509SVIDResponse_Result{
				Status: &types.Status{
					Code: int32(codes.OK),
				},
				Svid: svid,
			})
		default:
			results = append(results, &svidv1.BatchNewX509SVIDResponse_Result{
				Status: &types.Status{
					Code:    int32(codes.NotFound),
					Message: "svid not found",
				},
			})
		}
	}

	return &svidv1.BatchNewX509SVIDResponse{
		Results: results,
	}, nil
}

func (c *fakeSVIDServer) NewJWTSVID(context.Context, *svidv1.NewJWTSVIDRequest) (*svidv1.NewJWTSVIDResponse, error) {
	if c.newJWTSVID != nil {
		return nil, c.newJWTSVID
	}
	return &svidv1.NewJWTSVIDResponse{
		Svid: c.jwtSVID,
	}, nil
}

type fakeAgentServer struct {
	agentv1.UnimplementedAgentServer
	err  error
	svid *types.X509SVID
}

func (c *fakeAgentServer) RenewAgent(_ context.Context, in *agentv1.RenewAgentRequest) (*agentv1.RenewAgentResponse, error) {
	if c.err != nil {
		return nil, c.err
	}

	if in.Params == nil || len(in.Params.Csr) == 0 {
		return nil, errors.New("malformed param")
	}

	return &agentv1.RenewAgentResponse{
		Svid: c.svid,
	}, nil
}

type testServer struct {
	agentServer  *fakeAgentServer
	bundleServer *fakeBundleServer
	entryServer  *fakeEntryServer
	svidServer   *fakeSVIDServer
}

func checkAuthorizedEntryOutputMask(outputMask *types.EntryMask) error {
	if diff := cmp.Diff(outputMask, &types.EntryMask{
		SpiffeId:       true,
		Selectors:      true,
		FederatesWith:  true,
		Admin:          true,
		Downstream:     true,
		RevisionNumber: true,
		StoreSvid:      true,
		Hint:           true,
	}, protocmp.Transform()); diff != "" {
		return status.Errorf(codes.InvalidArgument, "invalid output mask requested: %s", diff)
	}
	return nil
}

func makeAPIBundle(trustDomainName string) *types.Bundle {
	return &types.Bundle{
		TrustDomain:     trustDomainName,
		X509Authorities: []*types.X509Certificate{{Asn1: []byte{10, 20, 30, 40}}},
	}
}

func makeCommonBundle(trustDomainName string) *common.Bundle {
	return &common.Bundle{
		TrustDomainId: "spiffe://" + trustDomainName,
		RootCas:       []*common.Certificate{{DerBytes: []byte{10, 20, 30, 40}}},
	}
}

func makeEntry(id string, revisionNumber int64) *types.Entry {
	return &types.Entry{
		Id:             id,
		SpiffeId:       &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
		ParentId:       &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
		Selectors:      []*types.Selector{{Type: "not", Value: "relevant"}},
		RevisionNumber: revisionNumber,
	}
}
