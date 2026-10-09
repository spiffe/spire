package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/entry/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
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

	testX509SVIDs = map[string]*X509SVID{
		"entry-id": {
			CertChain: []byte{11, 22, 33},
		},
	}

	testWITSVIDs = map[string]*WITSVID{
		"entry-id": {
			Token:     "SOME TOKEN",
			IssuedAt:  time.Unix(12345, 0).UTC(),
			ExpiresAt: time.Unix(54321, 0).UTC(),
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

func TestSyncUpdatesFederatedBundleRefresh(t *testing.T) {
	// Throttling needs both a configured minimum and a published refresh hint.
	// These are the values the behavioral subtests below configure: a 20m hint
	// asks to be polled every 5m, which is longer than the 1m floor.
	const (
		hint    = 20 * time.Minute
		minimum = time.Minute
		refresh = 5 * time.Minute
	)

	type harness struct {
		client        *client
		tc            *testServer
		clk           *clock.Mock
		cachedEntries map[string]*common.RegistrationEntry
		cachedBundles map[string]*common.Bundle
	}

	setup := func(t *testing.T, minInterval time.Duration, refreshHint int64) *harness {
		c, tc := createClient(t)
		clk := clock.NewMock(t)
		c.clk = clk
		c.c.MinFederatedBundleSyncInterval = minInterval

		domain1 := makeAPIBundle("domain1.test")
		domain1.RefreshHint = refreshHint

		tc.bundleServer.serverBundle = makeAPIBundle("example.org")
		tc.bundleServer.federatedBundles = map[string]*types.Bundle{
			"domain1.test": domain1,
			"domain2.test": makeAPIBundle("domain2.test"),
		}
		tc.entryServer.entries = []*types.Entry{
			{
				Id:            "0",
				SpiffeId:      &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
				ParentId:      &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
				Selectors:     []*types.Selector{{Type: "not", Value: "relevant"}},
				FederatesWith: []string{"domain1.test"},
			},
		}

		return &harness{
			client:        c,
			tc:            tc,
			clk:           clk,
			cachedEntries: make(map[string]*common.RegistrationEntry),
			cachedBundles: make(map[string]*common.Bundle),
		}
	}

	sync := func(t *testing.T, h *harness) {
		t.Helper()
		_, err := h.client.SyncUpdates(ctx, h.cachedEntries, h.cachedBundles)
		require.NoError(t, err)
	}

	// assertRefreshedAfter checks that domain1 is not refetched until the given
	// interval has elapsed, and is refetched once it has.
	assertRefreshedAfter := func(t *testing.T, h *harness, want time.Duration) {
		t.Helper()
		sync(t, h)
		require.Equal(t, 1, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))

		h.clk.Add(want - time.Second)
		sync(t, h)
		assert.Equal(t, 1, h.tc.bundleServer.federatedBundleCallCount("domain1.test"),
			"should not refresh before the interval elapses")
		assert.Contains(t, h.cachedBundles, "spiffe://domain1.test", "cached bundle should be retained")

		h.clk.Add(time.Second)
		sync(t, h)
		assert.Equal(t, 2, h.tc.bundleServer.federatedBundleCallCount("domain1.test"),
			"should refresh once the interval elapses")
	}

	// assertRefreshedEverySync checks that domain1 is refetched on every sync,
	// which is what an unthrottled agent does.
	assertRefreshedEverySync := func(t *testing.T, h *harness) {
		t.Helper()
		sync(t, h)
		require.Equal(t, 1, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))

		for i := 2; i < 5; i++ {
			h.clk.Add(time.Second)
			sync(t, h)
			assert.Equal(t, i, h.tc.bundleServer.federatedBundleCallCount("domain1.test"),
				"should refresh on every sync")
		}
	}

	t.Run("refreshes on every sync when no minimum is configured", func(t *testing.T) {
		// The default, and what an agent does without this setting.
		assertRefreshedEverySync(t, setup(t, 0, int64(hint.Seconds())))
	})

	t.Run("refreshes on every sync when no refresh hint is published", func(t *testing.T) {
		// There is nothing asking for a slower schedule, so the minimum does
		// not apply even though it is configured.
		assertRefreshedEverySync(t, setup(t, minimum, 0))
	})

	t.Run("honors the published refresh hint", func(t *testing.T) {
		assertRefreshedAfter(t, setup(t, minimum, int64(hint.Seconds())), refresh)
	})

	t.Run("clamps a refresh hint below the minimum refresh hint", func(t *testing.T) {
		// A hint under MinimumRefreshHint is raised to it before being divided,
		// then floored by the configured minimum.
		assertRefreshedAfter(t, setup(t, time.Second, 1),
			bundleutil.MinimumRefreshHint/federatedBundleRefreshAttempts)
	})

	t.Run("minimum interval overrides a shorter refresh hint", func(t *testing.T) {
		// A 4m hint asks for a 1m refresh, but the configured floor is longer.
		assertRefreshedAfter(t, setup(t, 10*time.Minute, int64((4*time.Minute).Seconds())), 10*time.Minute)
	})

	t.Run("a longer refresh hint wins over the minimum interval", func(t *testing.T) {
		assertRefreshedAfter(t, setup(t, time.Minute, int64((40*time.Minute).Seconds())), 10*time.Minute)
	})

	t.Run("fetches new federations immediately", func(t *testing.T) {
		h := setup(t, minimum, int64(hint.Seconds()))

		sync(t, h)
		require.Equal(t, 1, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))

		h.clk.Add(time.Second)
		h.tc.entryServer.entries[0].RevisionNumber++
		h.tc.entryServer.entries[0].FederatesWith = []string{"domain1.test", "domain2.test"}

		sync(t, h)
		assert.Equal(t, 1, h.tc.bundleServer.federatedBundleCallCount("domain1.test"),
			"already refreshed bundle should not be refetched")
		assert.Equal(t, 1, h.tc.bundleServer.federatedBundleCallCount("domain2.test"),
			"newly federated bundle should be fetched without waiting")
		assert.Contains(t, h.cachedBundles, "spiffe://domain2.test")
	})

	t.Run("drops bundles that are no longer federated", func(t *testing.T) {
		h := setup(t, minimum, int64(hint.Seconds()))

		sync(t, h)
		require.Contains(t, h.cachedBundles, "spiffe://domain1.test")

		h.clk.Add(time.Second)
		h.tc.entryServer.entries[0].RevisionNumber++
		h.tc.entryServer.entries[0].FederatesWith = nil

		sync(t, h)
		assert.Equal(t, map[string]*common.Bundle{
			"spiffe://example.org": makeCommonBundle("example.org"),
		}, h.cachedBundles)
		assert.NotContains(t, h.client.nextFederatedBundleSync, "spiffe://domain1.test",
			"schedule entry should be forgotten")
	})

	t.Run("evicts a bundle the server no longer has", func(t *testing.T) {
		h := setup(t, minimum, int64(hint.Seconds()))

		sync(t, h)
		require.Contains(t, h.cachedBundles, "spiffe://domain1.test")

		// The entry still federates with domain1, but the server has dropped the
		// bundle. The refresh must not keep serving the cached copy.
		delete(h.tc.bundleServer.federatedBundles, "domain1.test")
		h.tc.bundleServer.notFoundFederatedBundles = map[string]bool{"domain1.test": true}

		h.clk.Add(refresh)
		sync(t, h)
		assert.Equal(t, 2, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))
		assert.NotContains(t, h.cachedBundles, "spiffe://domain1.test",
			"a bundle the server no longer has should not remain cached")
	})

	t.Run("retains bundles that are not due for a refresh", func(t *testing.T) {
		h := setup(t, minimum, int64(hint.Seconds()))

		sync(t, h)
		require.Contains(t, h.cachedBundles, "spiffe://domain1.test")

		// Not due yet, so it is not refetched and must survive the eviction pass.
		h.clk.Add(refresh - time.Second)
		sync(t, h)
		assert.Equal(t, 1, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))
		want := makeCommonBundle("domain1.test")
		want.RefreshHint = int64(hint.Seconds())
		assert.Equal(t, want, h.cachedBundles["spiffe://domain1.test"])
	})

	t.Run("retries a trust domain the server has no bundle for", func(t *testing.T) {
		h := setup(t, minimum, int64(hint.Seconds()))
		// NotFound is not a sync failure, so the bundle never lands in the
		// cache. There is no hint to throttle against, so it stays due, which is
		// what makes a newly federated trust domain take effect promptly.
		delete(h.tc.bundleServer.federatedBundles, "domain1.test")
		h.tc.bundleServer.notFoundFederatedBundles = map[string]bool{"domain1.test": true}

		sync(t, h)
		require.Equal(t, 1, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))
		require.NotContains(t, h.cachedBundles, "spiffe://domain1.test")

		h.clk.Add(time.Second)
		sync(t, h)
		assert.Equal(t, 2, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))
	})

	t.Run("failed sync leaves the trust domain due", func(t *testing.T) {
		h := setup(t, minimum, int64(hint.Seconds()))

		sync(t, h)
		require.Equal(t, 1, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))

		h.clk.Add(refresh)
		h.tc.bundleServer.federatedBundleErr = errors.New("oh no")
		_, err := h.client.SyncUpdates(ctx, h.cachedEntries, h.cachedBundles)
		require.Error(t, err)
		require.Equal(t, 2, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))

		h.tc.bundleServer.federatedBundleErr = nil
		sync(t, h)
		assert.Equal(t, 3, h.tc.bundleServer.federatedBundleCallCount("domain1.test"),
			"a failed refresh should not push out the next refresh")
	})

	t.Run("warns when the minimum exceeds the refresh hint", func(t *testing.T) {
		const warning = "Federated bundle is refreshed less often than its trust domain requests; min_federated_bundle_sync_interval exceeds the bundle refresh hint"

		// warnings returns the refresh hint reported by each warning logged so
		// far, so the assertions below are not perturbed by other sync logs.
		warnings := func() []time.Duration {
			var out []time.Duration
			for _, e := range logHook.AllEntries() {
				if e.Message == warning {
					hint, ok := e.Data[telemetry.RefreshHint].(time.Duration)
					require.True(t, ok, "refresh hint should be logged as a duration")
					out = append(out, hint)
				}
			}
			return out
		}

		t.Run("silent when the hint is not exceeded", func(t *testing.T) {
			logHook.Reset()
			// A 20m hint asks for a 5m refresh, which the 1m minimum is under.
			h := setup(t, minimum, int64(hint.Seconds()))

			sync(t, h)
			h.clk.Add(refresh)
			sync(t, h)
			assert.Empty(t, warnings())
		})

		t.Run("warns once while the hint is unchanged", func(t *testing.T) {
			logHook.Reset()
			// A 4m hint asks for a 1m refresh, but the minimum is 10m.
			h := setup(t, 10*time.Minute, int64((4 * time.Minute).Seconds()))

			sync(t, h)
			spiretest.AssertLogsContainEntries(t, logHook.AllEntries(), []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: warning,
					Data: logrus.Fields{
						telemetry.FederatedBundle:                "spiffe://domain1.test",
						telemetry.RefreshHint:                    "4m0s",
						telemetry.MinFederatedBundleSyncInterval: "10m0s",
					},
				},
			})
			require.Len(t, warnings(), 1)

			h.clk.Add(10 * time.Minute)
			sync(t, h)
			require.Equal(t, 2, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))
			assert.Len(t, warnings(), 1, "should not repeat the warning for the same refresh hint")
		})

		t.Run("warns again when the published hint changes", func(t *testing.T) {
			logHook.Reset()
			h := setup(t, 10*time.Minute, int64((4 * time.Minute).Seconds()))

			sync(t, h)
			require.Equal(t, []time.Duration{4 * time.Minute}, warnings())

			// Still short enough to be exceeded by the minimum, but a hint the
			// warning has not reported yet.
			h.tc.bundleServer.federatedBundles["domain1.test"].RefreshHint = int64((8 * time.Minute).Seconds())
			h.clk.Add(10 * time.Minute)
			sync(t, h)
			require.Equal(t, 2, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))
			assert.Equal(t, []time.Duration{4 * time.Minute, 8 * time.Minute}, warnings())
		})

		t.Run("warns again after the condition clears", func(t *testing.T) {
			logHook.Reset()
			h := setup(t, 10*time.Minute, int64((4 * time.Minute).Seconds()))

			sync(t, h)
			require.Len(t, warnings(), 1)

			// A hint long enough to outrank the minimum clears the warned state.
			h.tc.bundleServer.federatedBundles["domain1.test"].RefreshHint = int64(time.Hour.Seconds())
			h.clk.Add(10 * time.Minute)
			sync(t, h)
			require.Len(t, warnings(), 1)

			h.tc.bundleServer.federatedBundles["domain1.test"].RefreshHint = int64((4 * time.Minute).Seconds())
			h.clk.Add(15 * time.Minute)
			sync(t, h)
			require.Equal(t, 3, h.tc.bundleServer.federatedBundleCallCount("domain1.test"))
			assert.Equal(t, []time.Duration{4 * time.Minute, 4 * time.Minute}, warnings())
		})
	})
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

	firstDate := time.Date(2024, time.December, 31, 0, 0, 0, 0, time.UTC)
	secondDate := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)

	entryA1 := makeEntry("A", 1, firstDate, nil)
	entryB1 := makeEntry("B", 1, firstDate, nil)
	entryC1 := makeEntry("C", 1, firstDate, nil)
	entryD1 := makeEntry("D", 1, firstDate, nil)

	entryA2 := makeEntry("A", 2, firstDate, nil)
	entryB2 := makeEntry("B", 2, firstDate, nil)
	entryC2 := makeEntry("C", 2, firstDate, nil)

	entryB1prime := makeEntry("B", 1, secondDate, nil)

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

	// Sync again after recreating an entry with the same entry ID, which should be marked stale
	syncAndAssertEntries(t, 3, 0, 1, 0, entryA2, entryB1prime, entryC2)

	// Sync again after the database has been rolled back to a previous version
	syncAndAssertEntries(t, 4, 1, 3, 0, entryA1, entryB1, entryC1, entryD1)
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
			testSvids:      testX509SVIDs,
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
			wg.Go(func() {
				svids, err = sClient.NewX509SVIDs(ctx, newTestCSRs())
			})

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

func newTestPublicKeys(t *testing.T) map[string]crypto.PublicKey {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return map[string]crypto.PublicKey{
		"entry-id": signer.Public(),
	}
}

func TestFetchReleaseWaitsForSyncUpdatesToFinish(t *testing.T) {
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

	cachedEntries := make(map[string]*common.RegistrationEntry)
	cachedBundles := make(map[string]*common.Bundle)
	_, err := client.SyncUpdates(ctx, cachedEntries, cachedBundles)
	require.NoError(t, err)

	assert.Equal(t, testBundles, cachedBundles)
	entry := testEntries[0]
	assert.Equal(t, entry, cachedEntries[entry.EntryId])
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
		_, r, err := client.newAgentClient()
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Create bundle client and release
		_, r, err = client.newBundleClient()
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Create entry client and release
		_, r, err = client.newEntryClient()
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)
		r.Release()

		// Create svid client and release
		_, r, err = client.newSVIDClient()
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
		_, conn, err := client.newAgentClient()
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)

		// Create bundle client
		_, conn, err = client.newBundleClient()
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)

		// Create entry client
		_, conn, err = client.newEntryClient()
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)

		// Create svid client
		_, conn, err = client.newSVIDClient()
		require.NoError(t, err)
		assertConnectionIsNotNil(t, client)

		client.release(conn)
		conn.Release()
		assertConnectionIsNil(t, client)
	}
}

func TestSyncUpdatesReleaseConnectionIfItFailsToFetch(t *testing.T) {
	client, tc := createClient(t)
	tc.bundleServer.bundleErr = errors.New("an error")

	cachedEntries := make(map[string]*common.RegistrationEntry)
	cachedBundles := make(map[string]*common.Bundle)
	stats, err := client.SyncUpdates(ctx, cachedEntries, cachedBundles)
	assert.Zero(t, stats)
	assert.EqualError(t, err, "failed to fetch bundle: rpc error: code = Unknown desc = an error")
	assertConnectionIsNil(t, client)
}

func TestSyncUpdatesAddStructuredLoggingIfCallToFetchBundlesFails(t *testing.T) {
	logHook.Reset()
	client, tc := createClient(t)

	tc.bundleServer.bundleErr = status.Error(codes.Internal, "call to grpc method fetchBundles has failed")
	cachedEntries := make(map[string]*common.RegistrationEntry)
	cachedBundles := make(map[string]*common.Bundle)
	stats, err := client.SyncUpdates(ctx, cachedEntries, cachedBundles)
	assert.Zero(t, stats)
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

func TestSyncUpdatesWithManyFederations(t *testing.T) {
	client, tc := createClient(t)

	// Create more federations than the number of workers in fetchFederatedBundlesConcurrently, to
	// test that they can each consume multiple jobs.
	const federationCount = 3 * defaultMaxBundleWorkers
	federatesWith := make([]string, federationCount)
	for i := range federationCount {
		federatesWith[i] = fmt.Sprintf("domain%d.test", i)
	}
	createdAt := time.Date(2024, time.December, 31, 0, 0, 0, 0, time.UTC)
	tc.entryServer.entries = []*types.Entry{
		makeEntry("ENTRYID1", 1234, createdAt, federatesWith),
	}

	tc.bundleServer.serverBundle = makeAPIBundle("example.org")
	tc.bundleServer.federatedBundles = make(map[string]*types.Bundle)
	for _, domain := range federatesWith {
		tc.bundleServer.federatedBundles[domain] = makeAPIBundle(domain)
	}

	cachedEntries := make(map[string]*common.RegistrationEntry)
	cachedBundles := make(map[string]*common.Bundle)
	_, err := client.SyncUpdates(ctx, cachedEntries, cachedBundles)

	// Assert results
	require.Nil(t, err)
	wantBundles := map[string]*common.Bundle{
		"spiffe://example.org": makeCommonBundle("example.org"),
	}
	for _, domain := range federatesWith {
		wantBundles["spiffe://"+domain] = makeCommonBundle(domain)
	}
	assert.Equal(t, wantBundles, cachedBundles)
	wantEntries := map[string]*common.RegistrationEntry{
		"ENTRYID1": makeCommonEntry("ENTRYID1", 1234, createdAt, federatesWith),
	}
	assert.Equal(t, wantEntries, cachedEntries)
	assertConnectionIsNotNil(t, client)
}

func TestFetchJWTSVID(t *testing.T) {
	client, tc := createClient(t)

	// Keep retries fast so the transient-error cases don't wait on real backoff.
	defer setJWTSVIDRetryInterval(time.Millisecond)()

	issuedAt := time.Now().Unix()
	expiresAt := time.Now().Add(time.Minute).Unix()
	for _, tt := range []struct {
		name           string
		setupTest      func(err error)
		err            string
		errIsPrefix    bool
		ctxTimeout     time.Duration
		expectSVID     *JWTSVID
		expectSPIFFEID spiffeid.ID
		fetchErr       error
	}{
		{
			name: "success",
			setupTest: func(err error) {
				tc.svidServer.jwtSVID = &types.JWTSVID{
					Token: "token",
					Id: &types.SPIFFEID{
						TrustDomain: "example.org",
						Path:        "/workload",
					},
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
			expectSPIFFEID: spiffeid.RequireFromString("spiffe://example.org/workload"),
		},
		{
			name: "transient error gives up when context expires",
			setupTest: func(err error) {
				tc.svidServer.newJWTSVID = err
			},
			// A transient error is retried until the context deadline, so only
			// the stable wrapper is asserted (the final error may be the injected
			// error or a context error, depending on timing).
			err:         "failed to fetch JWT SVID",
			errIsPrefix: true,
			ctxTimeout:  100 * time.Millisecond,
			fetchErr:    status.Error(codes.Unavailable, "server unavailable"),
		},
		{
			name: "permanent error returns immediately",
			setupTest: func(err error) {
				tc.svidServer.newJWTSVID = err
			},
			err:      "failed to fetch JWT SVID: rpc error: code = Unimplemented desc = unimplemented",
			fetchErr: status.Error(codes.Unimplemented, "unimplemented"),
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
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Reset any injected error from a previous case.
			tc.svidServer.newJWTSVID = nil
			tt.setupTest(tt.fetchErr)

			callCtx := ctx
			if tt.ctxTimeout > 0 {
				var cancel context.CancelFunc
				callCtx, cancel = context.WithTimeout(ctx, tt.ctxTimeout)
				defer cancel()
			}

			resp, spiffeId, err := client.NewJWTSVID(callCtx, "entry-id", []string{"myAud"}, false)
			if tt.err != "" {
				require.Nil(t, resp)
				if tt.errIsPrefix {
					require.ErrorContains(t, err, tt.err)
				} else {
					require.EqualError(t, err, tt.err)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, tt.expectSVID, resp)
			require.Equal(t, tt.expectSPIFFEID, spiffeId)
		})
	}
}

func TestNewJWTSVIDRetry(t *testing.T) {
	defer setJWTSVIDRetryInterval(time.Millisecond)()

	issuedAt := time.Now().Unix()
	expiresAt := time.Now().Add(time.Minute).Unix()
	goodSVID := &types.JWTSVID{
		Token: "token",
		Id: &types.SPIFFEID{
			TrustDomain: "example.org",
			Path:        "/workload",
		},
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
	}

	t.Run("retries transient errors until success", func(t *testing.T) {
		client, tc := createClient(t)
		tc.svidServer.jwtSVID = goodSVID
		tc.svidServer.newJWTSVID = status.Error(codes.Unavailable, "server unavailable")
		tc.svidServer.newJWTSVIDFailN = 2

		resp, spiffeID, err := client.NewJWTSVID(ctx, "entry-id", []string{"myAud"}, false)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, spiffeid.RequireFromString("spiffe://example.org/workload"), spiffeID)
		require.Equal(t, 3, tc.svidServer.newJWTSVIDCallCount(), "should retry twice before succeeding")
	})

	t.Run("does not retry permanent errors", func(t *testing.T) {
		client, tc := createClient(t)
		tc.svidServer.newJWTSVID = status.Error(codes.Unimplemented, "unimplemented")

		resp, _, err := client.NewJWTSVID(ctx, "entry-id", []string{"myAud"}, false)
		require.Nil(t, resp)
		require.EqualError(t, err, "failed to fetch JWT SVID: rpc error: code = Unimplemented desc = unimplemented")
		require.Equal(t, 1, tc.svidServer.newJWTSVIDCallCount(), "permanent errors must not be retried")
	})

	t.Run("gives up when the context expires", func(t *testing.T) {
		client, tc := createClient(t)
		tc.svidServer.newJWTSVID = status.Error(codes.Unavailable, "server unavailable")

		callCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		resp, _, err := client.NewJWTSVID(callCtx, "entry-id", []string{"myAud"}, false)
		require.Nil(t, resp)
		require.ErrorContains(t, err, "failed to fetch JWT SVID")
		require.Greater(t, tc.svidServer.newJWTSVIDCallCount(), 1, "should have retried more than once")
	})
}

// setJWTSVIDRetryInterval overrides the NewJWTSVID retry backoff interval and
// returns a function that restores the previous value.
func setJWTSVIDRetryInterval(d time.Duration) func() {
	prev := jwtSVIDRetryInterval
	jwtSVIDRetryInterval = d
	return func() { jwtSVIDRetryInterval = prev }
}

func TestNewWITSVIDs(t *testing.T) {
	logHook.Reset()

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
	witSVIDs := map[string]*types.WITSVID{
		"entry-id": {
			Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
			Token:     "SOME TOKEN",
			IssuedAt:  12345,
			ExpiresAt: 54321,
		},
	}

	tests := []struct {
		name           string
		entries        []*types.Entry
		witSVIDs       map[string]*types.WITSVID
		batchSVIDErr   error
		wantError      assert.ErrorAssertionFunc
		assertFuncConn func(t *testing.T, client *client)
		testSvids      map[string]*WITSVID
		expectedLogs   []spiretest.LogEntry
	}{
		{
			name:           "success",
			entries:        entries,
			witSVIDs:       witSVIDs,
			batchSVIDErr:   nil,
			wantError:      assert.NoError,
			assertFuncConn: assertConnectionIsNotNil,
			testSvids:      testWITSVIDs,
		},
		{
			name:           "failed",
			entries:        entries,
			witSVIDs:       witSVIDs,
			batchSVIDErr:   status.Error(codes.NotFound, "not found when executing BatchNewWITSVID"),
			wantError:      assert.Error,
			assertFuncConn: assertConnectionIsNil,
			testSvids:      nil,
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to batch new WIT-SVID(s)",
					Data: logrus.Fields{
						telemetry.StatusCode:    "NotFound",
						telemetry.StatusMessage: "not found when executing BatchNewWITSVID",
						logrus.ErrorKey:         "rpc error: code = NotFound desc = not found when executing BatchNewWITSVID",
					},
				},
			},
		},
		{
			name:    "missing SVID",
			entries: entries,
			witSVIDs: map[string]*types.WITSVID{
				"entry-id": nil,
			},
			wantError:      assert.NoError,
			assertFuncConn: assertConnectionIsNotNil,
			testSvids:      map[string]*WITSVID{},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid WIT-SVID",
					Data: logrus.Fields{
						telemetry.RegistrationID: "entry-id",
						logrus.ErrorKey:          "WITSVID response missing SVID",
					},
				},
			},
		},
		{
			name:    "missing issued at",
			entries: entries,
			witSVIDs: map[string]*types.WITSVID{
				"entry-id": {
					Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
					Token:     "SOME TOKEN",
					ExpiresAt: 54321,
				},
			},
			wantError:      assert.NoError,
			assertFuncConn: assertConnectionIsNotNil,
			testSvids:      map[string]*WITSVID{},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid WIT-SVID",
					Data: logrus.Fields{
						telemetry.RegistrationID: "entry-id",
						logrus.ErrorKey:          "WITSVID missing issued at",
					},
				},
			},
		},
		{
			name:    "missing expires at",
			entries: entries,
			witSVIDs: map[string]*types.WITSVID{
				"entry-id": {
					Id:       &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
					Token:    "SOME TOKEN",
					IssuedAt: 12345,
				},
			},
			wantError:      assert.NoError,
			assertFuncConn: assertConnectionIsNotNil,
			testSvids:      map[string]*WITSVID{},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid WIT-SVID",
					Data: logrus.Fields{
						telemetry.RegistrationID: "entry-id",
						logrus.ErrorKey:          "WITSVID missing expires at",
					},
				},
			},
		},
		{
			name:    "issued after expired",
			entries: entries,
			witSVIDs: map[string]*types.WITSVID{
				"entry-id": {
					Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/path"},
					Token:     "SOME TOKEN",
					IssuedAt:  54321,
					ExpiresAt: 12345,
				},
			},
			wantError:      assert.NoError,
			assertFuncConn: assertConnectionIsNotNil,
			testSvids:      map[string]*WITSVID{},
			expectedLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid WIT-SVID",
					Data: logrus.Fields{
						telemetry.RegistrationID: "entry-id",
						logrus.ErrorKey:          "WITSVID issued after it has expired",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc.entryServer.entries = tt.entries
			tc.svidServer.witSVIDs = tt.witSVIDs
			tc.svidServer.batchSVIDErr = tt.batchSVIDErr

			// Simulate an ongoing SVID rotation (request should not be made in the middle of a rotation)
			sClient.c.RotMtx.Lock()

			// Do the request in a different go routine
			var wg sync.WaitGroup
			var svids map[string]*WITSVID
			err := errors.New("a not nil error")
			wg.Go(func() {
				svids, err = sClient.NewWITSVIDs(ctx, newTestPublicKeys(t), "ES256")
			})

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

	client.dialOpts = []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
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
}

func (c *fakeEntryServer) SetEntries(entries ...*types.Entry) {
	c.entries = entries
}

func (c *fakeEntryServer) SyncAuthorizedEntries(stream entryv1.Entry_SyncAuthorizedEntriesServer) error {
	const entryPageSize = 2

	entries := []api.ReadOnlyEntry{}
	for _, entry := range c.entries {
		entries = append(entries, api.NewReadOnlyEntry(entry))
	}

	return entry.SyncAuthorizedEntries(stream, entries, entryPageSize)
}

type fakeBundleServer struct {
	bundlev1.UnimplementedBundleServer

	serverBundle       *types.Bundle
	federatedBundles   map[string]*types.Bundle
	bundleErr          error
	federatedBundleErr error

	// notFoundFederatedBundles are trust domains the server reports as having
	// no bundle, which is not a sync failure.
	notFoundFederatedBundles map[string]bool

	simulateRelease func()

	mu                   sync.Mutex
	federatedBundleCalls map[string]int
}

// federatedBundleCallCount returns how many times the given trust domain has
// been requested, including requests that returned an error.
func (c *fakeBundleServer) federatedBundleCallCount(trustDomain string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.federatedBundleCalls[trustDomain]
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
	c.mu.Lock()
	if c.federatedBundleCalls == nil {
		c.federatedBundleCalls = make(map[string]int)
	}
	c.federatedBundleCalls[in.TrustDomain]++
	c.mu.Unlock()

	if c.federatedBundleErr != nil {
		return nil, c.federatedBundleErr
	}
	if c.notFoundFederatedBundles[in.TrustDomain] {
		return nil, status.Error(codes.NotFound, "bundle not found")
	}
	b, ok := c.federatedBundles[in.TrustDomain]
	if !ok {
		return nil, errors.New("no federated bundle found")
	}

	return b, nil
}

type fakeSVIDServer struct {
	svidv1.UnimplementedSVIDServer

	mu              sync.Mutex
	batchSVIDErr    error
	newJWTSVID      error
	newJWTSVIDFailN int // number of initial NewJWTSVID calls that fail; 0 means every call fails while newJWTSVID is set
	newJWTSVIDCalls int
	x509SVIDs       map[string]*types.X509SVID
	jwtSVID         *types.JWTSVID
	witSVIDs        map[string]*types.WITSVID
	simulateRelease func()
}

func (c *fakeSVIDServer) newJWTSVIDCallCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.newJWTSVIDCalls
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
	c.mu.Lock()
	c.newJWTSVIDCalls++
	call := c.newJWTSVIDCalls
	c.mu.Unlock()

	if c.newJWTSVID != nil && (c.newJWTSVIDFailN == 0 || call <= c.newJWTSVIDFailN) {
		return nil, c.newJWTSVID
	}
	return &svidv1.NewJWTSVIDResponse{
		Svid: c.jwtSVID,
	}, nil
}

func (c *fakeSVIDServer) BatchNewWITSVID(_ context.Context, in *svidv1.BatchNewWITSVIDRequest) (*svidv1.BatchNewWITSVIDResponse, error) {
	if c.batchSVIDErr != nil {
		return nil, c.batchSVIDErr
	}

	// Simulate async calls
	if c.simulateRelease != nil {
		go c.simulateRelease()
	}

	var results []*svidv1.BatchNewWITSVIDResponse_Result
	for _, param := range in.Params {
		svid, ok := c.witSVIDs[param.EntryId]
		switch {
		case ok:
			results = append(results, &svidv1.BatchNewWITSVIDResponse_Result{
				Status: &types.Status{
					Code: int32(codes.OK),
				},
				Svid: svid,
			})
		default:
			results = append(results, &svidv1.BatchNewWITSVIDResponse_Result{
				Status: &types.Status{
					Code:    int32(codes.NotFound),
					Message: "svid not found",
				},
			})
		}
	}

	return &svidv1.BatchNewWITSVIDResponse{
		Results: results,
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

func makeEntry(id string, revisionNumber int64, createdAt time.Time, federatesWith []string) *types.Entry {
	return &types.Entry{
		Id:             id,
		SpiffeId:       &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
		ParentId:       &types.SPIFFEID{TrustDomain: "example.org", Path: "/agent"},
		Selectors:      []*types.Selector{{Type: "not", Value: "relevant"}},
		RevisionNumber: revisionNumber,
		CreatedAt:      createdAt.Unix(),
		FederatesWith:  slices.Clone(federatesWith),
	}
}

func makeCommonEntry(id string, revisionNumber int64, createdAt time.Time, federatesWith []string) *common.RegistrationEntry {
	var federatesWithIds []string
	for _, domain := range federatesWith {
		federatesWithIds = append(federatesWithIds, "spiffe://"+domain)
	}
	return &common.RegistrationEntry{
		EntryId:        id,
		SpiffeId:       "spiffe://example.org/workload",
		Selectors:      []*common.Selector{{Type: "not", Value: "relevant"}},
		RevisionNumber: revisionNumber,
		CreatedAt:      createdAt.Unix(),
		FederatesWith:  federatesWithIds,
	}
}
