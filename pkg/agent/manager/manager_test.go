package manager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	testlog "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/pkg/agent/trustbundlesources"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakeagentkeymanager"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/spiffe/spire/test/testkey"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var (
	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")
	agentID     = spiffeid.RequireFromPath(trustDomain, "/agent")
	joinTokenID = spiffeid.RequireFromPath(trustDomain, "/spire/agent/join_token/abcd")

	serverKey = testkey.MustEC256()
)

var (
	testLogger, _ = testlog.NewNullLogger()
	regEntriesMap = util.GetRegistrationEntriesMap("manager_test_entries.json")
)

func TestInitializationFailure(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	ca, caKey := createCA(t, clk)
	baseSVID, baseSVIDKey := createSVID(t, km, clk, ca, caKey, agentID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	sto := openStorage(t, dir)
	ts := &trustbundlesources.Config{
		InsecureBootstrap:     false,
		TrustBundleFormat:     "pem",
		TrustBundlePath:       "",
		TrustBundleURL:        "",
		TrustBundleUnixSocket: "",
		TrustDomain:           "example.org",
		ServerAddress:         "localhost",
		ServerPort:            1234,
	}

	tbs := trustbundlesources.New(ts, nil)
	tbs.SetMetrics(&telemetry.Blackhole{})
	err := tbs.SetStorage(sto)
	require.NoError(t, err)

	c := &Config{
		SVID:               baseSVID,
		SVIDKey:            baseSVIDKey,
		Log:                testLogger,
		Metrics:            &telemetry.Blackhole{},
		TrustDomain:        trustDomain,
		TrustBundleSources: tbs,
		Storage:            sto,
		Clk:                clk,
		Catalog:            cat,
		SVIDStoreCache:     storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
	}
	m := newManager(c)
	require.Error(t, m.Initialize(context.Background()))
}

func TestStoreBundleOnStartup(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	ca, caKey := createCA(t, clk)
	baseSVID, baseSVIDKey := createSVID(t, km, clk, ca, caKey, agentID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	sto := openStorage(t, dir)

	c := &Config{
		SVID:        baseSVID,
		SVIDKey:     baseSVIDKey,
		Log:         testLogger,
		Metrics:     &telemetry.Blackhole{},
		TrustDomain: trustDomain,
		Storage:     sto,
		Bundle:      spiffebundle.FromX509Authorities(trustDomain, []*x509.Certificate{ca}),
		Clk:         clk,
		Catalog:     cat,
	}

	m := newManager(c)

	util.RunWithTimeout(t, time.Second, func() {
		sub := m.SubscribeToBundleChanges()
		bundles := sub.Value()
		require.NotNil(t, bundles)
		bundle := bundles[trustDomain]
		require.Equal(t, bundle.X509Authorities(), []*x509.Certificate{ca})
	})

	require.Error(t, m.Initialize(context.Background()))

	// Although init failed, the bundle should have been saved, because it should be
	// one of the first thing the manager does at initialization.
	bundle, err := sto.LoadBundle()
	if err != nil {
		t.Fatalf("bundle should have been saved in a file: %v", err)
	}

	if !bundle[0].Equal(ca) {
		t.Fatal("bundle should have included CA certificate")
	}
}

func TestStoreSVIDOnStartup(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	ca, caKey := createCA(t, clk)
	baseSVID, baseSVIDKey := createSVID(t, km, clk, ca, caKey, agentID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	sto := openStorage(t, dir)

	c := &Config{
		SVID:         baseSVID,
		SVIDKey:      baseSVIDKey,
		Reattestable: true,
		Log:          testLogger,
		Metrics:      &telemetry.Blackhole{},
		TrustDomain:  trustDomain,
		Storage:      sto,
		Clk:          clk,
		Catalog:      cat,
	}

	if _, _, err := sto.LoadSVID(); !errors.Is(err, storage.ErrNotCached) {
		t.Fatalf("wanted: %v, got: %v", storage.ErrNotCached, err)
	}

	m := newManager(c)

	if err := m.Initialize(context.Background()); err == nil {
		t.Fatal("manager was expected to fail during initialization")
	}

	// Although start failed, the SVID should have been saved, because it should be
	// one of the first thing the manager does at initialization.
	svid, reattestable, err := sto.LoadSVID()
	if err != nil {
		t.Fatal(err)
	}
	if !svidsEqual(svid, baseSVID) {
		t.Fatal("SVID was not correctly stored.")
	}
	require.True(t, reattestable)
}

func TestHappyPathWithoutSyncNorRotation(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(*mockAPI, int32, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		svidTTL: 200,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)

	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		WorkloadKeyType:  workloadkey.ECP256,
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		Clk:              clk,
		Catalog:          cat,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m, closer := initializeAndRunNewManager(t, c)
	defer closer()

	svid := m.svid.State().SVID
	if !svidsEqual(svid, baseSVID) {
		t.Fatal("SVID is not equals to configured one")
	}

	key := m.svid.State().Key
	if key != baseSVIDKey {
		t.Fatal("PrivateKey is not equals to configured one")
	}

	matches := m.MatchingRegistrationEntries(cache.Selectors{{Type: "unix", Value: "uid:1111"}})
	if len(matches) != 2 {
		t.Fatal("expected 2 registration entries")
	}

	// Verify bundle
	require.Equal(t, api.bundle, m.GetBundle())

	// Expect three SVIDs on cache
	require.Equal(t, 3, m.CountX509SVIDs())

	// Expect last sync
	require.Equal(t, clk.Now(), m.GetLastSync())

	compareRegistrationEntries(t,
		regEntriesMap["resp2"],
		[]*common.RegistrationEntry{matches[0], matches[1]})

	util.RunWithTimeout(t, 5*time.Second, func() {
		sub, err := m.SubscribeToCacheChanges(context.Background(), cache.Selectors{{Type: "unix", Value: "uid:1111"}})
		require.NoError(t, err)
		u := <-sub.Updates()

		if len(u.Identities) != 2 {
			t.Fatal("expected 2 entries")
		}

		if len(u.Bundle.X509Authorities()) != 1 {
			t.Fatal("expected 1 bundle root CA")
		}

		if !u.Bundle.Equal(api.bundle) {
			t.Fatal("received bundle should be equals to the server bundle")
		}

		compareRegistrationEntries(t,
			regEntriesMap["resp2"],
			[]*common.RegistrationEntry{u.Identities[0].Entry, u.Identities[1].Entry})
	})
}

func TestRotationWithRSAKey(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(*mockAPI, int32, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		svidTTL: 200,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)

	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		Clk:              clk,
		Catalog:          cat,
		WorkloadKeyType:  workloadkey.RSA2048,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m, closer := initializeAndRunNewManager(t, c)
	defer closer()

	svid := m.svid.State().SVID
	if !svidsEqual(svid, baseSVID) {
		t.Fatal("SVID is not equals to configured one")
	}

	key := m.svid.State().Key
	if key != baseSVIDKey {
		t.Fatal("PrivateKey is not equals to configured one")
	}

	matches := m.MatchingRegistrationEntries(cache.Selectors{{Type: "unix", Value: "uid:1111"}})
	if len(matches) != 2 {
		t.Fatal("expected 2 registration entries")
	}

	// Verify bundle
	require.Equal(t, api.bundle, m.GetBundle())

	// Expect three SVIDs on cache
	require.Equal(t, 3, m.CountX509SVIDs())

	// Expect last sync
	require.Equal(t, clk.Now(), m.GetLastSync())

	compareRegistrationEntries(t,
		regEntriesMap["resp2"],
		[]*common.RegistrationEntry{matches[0], matches[1]})

	util.RunWithTimeout(t, 5*time.Second, func() {
		sub, err := m.SubscribeToCacheChanges(context.Background(), cache.Selectors{{Type: "unix", Value: "uid:1111"}})
		require.NoError(t, err)
		u := <-sub.Updates()

		if len(u.Identities) != 2 {
			t.Fatal("expected 2 entries")
		}

		if len(u.Bundle.X509Authorities()) != 1 {
			t.Fatal("expected 1 bundle root CA")
		}

		if !u.Bundle.Equal(api.bundle) {
			t.Fatal("received bundle should be equals to the server bundle")
		}

		compareRegistrationEntries(t,
			regEntriesMap["resp2"],
			[]*common.RegistrationEntry{u.Identities[0].Entry, u.Identities[1].Entry})
	})
}

func TestSVIDRotation(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)

	baseTTLSeconds := 3
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(*mockAPI, int32, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		svidTTL: baseTTLSeconds,
		clk:     clk,
	})

	baseTTL := time.Duration(baseTTLSeconds) * time.Second
	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, baseTTL)

	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	c := &Config{
		Catalog:          cat,
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: baseTTL / 2,
		SyncInterval:     1 * time.Hour,
		Clk:              clk,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m := initializeNewManager(t, c)

	svid := m.svid.State().SVID
	if !svidsEqual(svid, baseSVID) {
		t.Fatal("SVID is not equals to configured one")
	}

	key := m.svid.State().Key
	if key != baseSVIDKey {
		t.Fatal("PrivateKey is not equals to configured one")
	}
	require.Equal(t, clk.Now(), m.lastSync)

	// Define and set a rotation hook
	rotHookStatus := struct {
		called bool
		mtx    sync.RWMutex
	}{}

	wasRotHookCalled := func() bool {
		rotHookStatus.mtx.RLock()
		defer rotHookStatus.mtx.RUnlock()
		return rotHookStatus.called
	}

	m.SetRotationFinishedHook(func() {
		rotHookStatus.mtx.Lock()
		defer rotHookStatus.mtx.Unlock()
		rotHookStatus.called = true
	})

	// Get RLock to simulate an ongoing request (Rotator should wait until mtx is unlocked)
	m.GetRotationMtx().RLock()

	// Now advance time enough that the cert is expiring soon enough that the
	// manager will attempt to rotate, but be unable to since the read lock is
	// held.
	clk.Add(baseTTL)

	closer := runManager(t, m)
	defer closer()

	// Loop, we should not detect SVID rotations
	for range 10 {
		s := m.GetCurrentCredentials()
		svid = s.SVID
		require.True(t, svidsEqual(svid, baseSVID))
		require.False(t, wasRotHookCalled())
		clk.Add(100 * time.Millisecond)
	}

	// RUnlock simulates the end of the request (Rotator should rotate SVIDs now)
	m.GetRotationMtx().RUnlock()

	// Loop until we detect an SVID rotation was called in separate process
	require.Eventually(t, wasRotHookCalled, time.Minute, 100*time.Millisecond)

	s := m.GetCurrentCredentials()
	svid = s.SVID
	key = s.Key
	require.False(t, svidsEqual(svid, baseSVID))

	if key == baseSVIDKey {
		t.Fatal("PrivateKey did not rotate")
	}
}

func TestSynchronization(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	ttl := 3
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(*mockAPI, int32, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		svidTTL: ttl,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: time.Hour,
		SyncInterval:     time.Hour,
		Clk:              clk,
		Catalog:          cat,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)

	sub, err := m.SubscribeToCacheChanges(context.Background(), cache.Selectors{
		{Type: "unix", Value: "uid:1111"},
		{Type: "spiffe_id", Value: joinTokenID.String()},
	})
	require.NoError(t, err)
	defer sub.Finish()

	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, clk.Now(), m.GetLastSync())

	// Before synchronization
	identitiesBefore := identitiesByEntryID(m.cache.Identities())
	if len(identitiesBefore) != 3 {
		t.Fatalf("3 cached identities were expected; got %d", len(identitiesBefore))
	}

	// This is the initial update based on the selector set
	u := <-sub.Updates()
	if len(u.Identities) != 3 {
		t.Fatalf("expected 3 identities, got: %d", len(u.Identities))
	}

	if len(u.Bundle.X509Authorities()) != 1 {
		t.Fatal("expected 1 bundle root CA")
	}

	if !u.Bundle.Equal(api.bundle) {
		t.Fatal("received bundle should be equals to the server bundle")
	}

	for key, eu := range identitiesByEntryID(u.Identities) {
		eb, ok := identitiesBefore[key]
		if !ok {
			t.Fatalf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
		}
		require.Equal(t, eb, eu, "identity received does not match identity on cache")
	}

	require.Equal(t, clk.Now(), m.GetLastSync())

	// SVIDs expire after 3 seconds, so we shouldn't expect any updates after
	// 1 second has elapsed.
	clk.Add(time.Second)
	require.NoError(t, m.synchronize(context.Background()))
	select {
	case <-sub.Updates():
		t.Fatal("update unexpected after 1 second")
	default:
	}

	// After advancing another second, the SVIDs should have been refreshed,
	// since the half-time has been exceeded.
	clk.Add(time.Second)
	require.NoError(t, m.synchronize(context.Background()))
	select {
	case u = <-sub.Updates():
	default:
		t.Fatal("update expected after 2 seconds")
	}

	// Make sure the update contains the updated entries and that the cache
	// has a consistent view.
	identitiesAfter := identitiesByEntryID(m.cache.Identities())
	if len(identitiesAfter) != 3 {
		t.Fatalf("expected 3 identities, got: %d", len(identitiesAfter))
	}

	for key, eb := range identitiesBefore {
		ea, ok := identitiesAfter[key]
		if !ok {
			t.Fatalf("expected identity with EntryId=%v after synchronization", key)
		}
		require.NotEqual(t, eb, ea, "there is at least one identity that was not refreshed: %v", ea)
	}

	if len(u.Identities) != 3 {
		t.Fatalf("expected 3 identities, got: %d", len(u.Identities))
	}

	if len(u.Bundle.X509Authorities()) != 1 {
		t.Fatal("expected 1 bundle root CA")
	}

	if !u.Bundle.Equal(api.bundle) {
		t.Fatal("received bundle should be equals to the server bundle")
	}

	for key, eu := range identitiesByEntryID(u.Identities) {
		ea, ok := identitiesAfter[key]
		if !ok {
			t.Fatalf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
		}
		require.Equal(t, eu, ea, "entry received does not match entry on cache")
	}

	require.Equal(t, clk.Now(), m.GetLastSync())
}

func TestSynchronizationClearsStaleCacheEntries(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(h *mockAPI, count int32, _ *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			switch count {
			case 1:
				return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
			case 2:
				return makeGetAuthorizedEntriesResponse(t, "resp1"), nil
			default:
				return nil, fmt.Errorf("unexpected getAuthorizedEntries call count: %d", count)
			}
		},
		batchNewX509SVIDEntries: func(h *mockAPI, count int32) []*common.RegistrationEntry {
			switch count {
			case 1:
				return makeBatchNewX509SVIDEntries("resp1", "resp2")
			case 2:
				return makeBatchNewX509SVIDEntries("resp1")
			default:
				return nil
			}
		},
		svidTTL: 3,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		Clk:              clk,
		Catalog:          cat,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)

	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// after initialization, the cache should contain both resp1 and resp2
	// entries.
	compareRegistrationEntries(t,
		append(regEntriesMap["resp1"], regEntriesMap["resp2"]...),
		m.cache.Entries())

	// manually synchronize again
	if err := m.synchronize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// now the cache should have entries from resp2 removed
	compareRegistrationEntries(t,
		regEntriesMap["resp1"],
		m.cache.Entries())
}

func TestSynchronizationUpdatesRegistrationEntries(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(h *mockAPI, count int32, req *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			switch count {
			case 1:
				return makeGetAuthorizedEntriesResponse(t, "resp2"), nil
			case 2:
				return makeGetAuthorizedEntriesResponse(t, "resp3"), nil
			default:
				return nil, fmt.Errorf("unexpected getAuthorizedEntries call count: %d", count)
			}
		},
		batchNewX509SVIDEntries: func(h *mockAPI, count int32) []*common.RegistrationEntry {
			switch count {
			case 1:
				return makeBatchNewX509SVIDEntries("resp2")
			case 2:
				return makeBatchNewX509SVIDEntries("resp3")
			default:
				return nil
			}
		},
		svidTTL: 3,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		Clk:              clk,
		Catalog:          cat,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)

	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// after initialization, the cache should contain resp2 entries
	compareRegistrationEntries(t,
		regEntriesMap["resp2"],
		m.cache.Entries())

	// manually synchronize again
	if err := m.synchronize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// now the cache should have the updated entries from resp3
	compareRegistrationEntries(t,
		regEntriesMap["resp3"],
		m.cache.Entries())
}

func TestForceRotation(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	// Big number to never get into regular rotation
	ttl := 10000
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(*mockAPI, int32, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		svidTTL: ttl,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	log, logHook := testlog.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              log,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: time.Hour,
		SyncInterval:     time.Hour,
		Clk:              clk,
		Catalog:          cat,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger, Metrics: &telemetry.Blackhole{}}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)

	sub, err := m.SubscribeToCacheChanges(context.Background(), cache.Selectors{
		{Type: "unix", Value: "uid:1111"},
		{Type: "spiffe_id", Value: joinTokenID.String()},
	})
	require.NoError(t, err)
	defer sub.Finish()

	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, clk.Now(), m.GetLastSync())

	// Before synchronization
	identitiesBefore := identitiesByEntryID(m.cache.Identities())
	if len(identitiesBefore) != 3 {
		t.Fatalf("3 cached identities were expected; got %d", len(identitiesBefore))
	}

	// This is the initial update based on the selector set
	u := <-sub.Updates()
	if len(u.Identities) != 3 {
		t.Fatalf("expected 3 identities, got: %d", len(u.Identities))
	}

	if len(u.Bundle.X509Authorities()) != 1 {
		t.Fatal("expected 1 bundle root CA")
	}

	if !u.Bundle.Equal(api.bundle) {
		t.Fatal("received bundle should be equals to the server bundle")
	}

	for key, eu := range identitiesByEntryID(u.Identities) {
		eb, ok := identitiesBefore[key]
		if !ok {
			t.Fatalf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
		}
		require.Equal(t, eb, eu, "identity received does not match identity on cache")
	}

	require.Equal(t, clk.Now(), m.GetLastSync())

	// No ttl and bundle updates
	clk.Add(time.Second)
	require.NoError(t, m.synchronize(context.Background()))
	select {
	case <-sub.Updates():
		t.Fatal("update unexpected after 1 second")
	default:
	}
	assert.False(t, m.svid.IsTainted())

	// Taint authority
	api.taintCurrentX509Authority()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Initial synchronization
	require.NoError(t, m.synchronize(ctx))

	// Wait until tainted authorities are fully processed, then retry synchronization
	assert.Eventually(t, func() bool {
		for _, logEntry := range logHook.AllEntries() {
			if logEntry.Message == "Finished processing all tainted entries" {
				return true
			}
		}
		return false
	}, time.Minute, 50*time.Millisecond, "No tainted authority processed")

	// Retry synchronization to handle potential edge case
	require.NoError(t, m.synchronize(ctx))

	select {
	case u = <-sub.Updates():
	case <-ctx.Done():
		t.Fatal("Expected update after tainting authority, but none received")
	}

	// SVID is signed by a tainted authority, it must be tainted
	assert.True(t, m.svid.IsTainted())
	taintedSubjectKeyID := x509util.SubjectKeyIDToString(api.taintedX509Authority.SubjectKeyId)
	expectProcessedTaintedX509Authorities := map[string]struct{}{
		taintedSubjectKeyID: {},
	}
	assert.Equal(t, expectProcessedTaintedX509Authorities, m.processedTaintedX509Authorities)

	// Make sure the update contains the updated entries and that the cache
	// has a consistent view.
	identitiesAfter := identitiesByEntryID(m.cache.Identities())
	if len(identitiesAfter) != 3 {
		t.Fatalf("expected 3 identities, got: %d", len(identitiesAfter))
	}

	for key, eb := range identitiesBefore {
		ea, ok := identitiesAfter[key]
		if !ok {
			t.Fatalf("expected identity with EntryId=%v after synchronization", key)
		}
		require.NotEqual(t, eb, ea, "there is at least one identity that was not refreshed: %v", ea)
	}

	if len(u.Identities) != 3 {
		t.Fatalf("expected 3 identities, got: %d", len(u.Identities))
	}

	if len(u.Bundle.X509Authorities()) != 2 {
		t.Fatal("expected 1 bundle root CA")
	}

	if !u.Bundle.Equal(api.bundle) {
		t.Fatal("received bundle should be equals to the server bundle")
	}

	for key, eu := range identitiesByEntryID(u.Identities) {
		ea, ok := identitiesAfter[key]
		if !ok {
			t.Fatalf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
		}
		require.Equal(t, eu, ea, "entry received does not match entry on cache")
	}

	require.Equal(t, clk.Now(), m.GetLastSync())
}

func TestSubscribersGetUpToDateBundle(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(h *mockAPI, count int32, req *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(h *mockAPI, count int32) []*common.RegistrationEntry {
			h.rotateCA()
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		svidTTL: 200,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: 1 * time.Hour,
		SyncInterval:     1 * time.Hour,
		Clk:              clk,
		Catalog:          cat,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)

	defer initializeAndRunManager(t, m)()
	sub, err := m.SubscribeToCacheChanges(context.Background(), cache.Selectors{{Type: "unix", Value: "uid:1111"}})
	require.NoError(t, err)

	util.RunWithTimeout(t, 1*time.Second, func() {
		// Update should contain a new bundle.
		u := <-sub.Updates()
		if len(u.Bundle.X509Authorities()) != 2 {
			t.Fatalf("expected 2 bundles, got: %d", len(u.Bundle.X509Authorities()))
		}
		if !u.Bundle.Equal(c.Bundle) {
			t.Fatal("bundles were expected to be equal")
		}
	})
}

func TestSynchronizationWithLRUCache(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	ttl := 3
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(*mockAPI, int32, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		svidTTL: ttl,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	c := &Config{
		ServerAddr:           api.addr,
		SVID:                 baseSVID,
		SVIDKey:              baseSVIDKey,
		Log:                  testLogger,
		TrustDomain:          trustDomain,
		Storage:              openStorage(t, dir),
		Bundle:               api.bundle,
		Metrics:              &telemetry.Blackhole{},
		RotationInterval:     time.Hour,
		SyncInterval:         time.Hour,
		Clk:                  clk,
		Catalog:              cat,
		WorkloadKeyType:      workloadkey.ECP256,
		X509SVIDCacheMaxSize: 10,
		JWTSVIDCacheMaxSize:  10,
		SVIDStoreCache:       storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy:     rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)

	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, clk.Now(), m.GetLastSync())

	sub, err := m.SubscribeToCacheChanges(context.Background(), cache.Selectors{
		{Type: "unix", Value: "uid:1111"},
		{Type: "spiffe_id", Value: joinTokenID.String()},
	})
	require.NoError(t, err)
	defer sub.Finish()

	// Before synchronization
	identitiesBefore := identitiesByEntryID(m.cache.Identities())
	if len(identitiesBefore) != 3 {
		t.Fatalf("3 cached identities were expected; got %d", len(identitiesBefore))
	}

	// This is the initial update based on the selector set
	u := <-sub.Updates()
	if len(u.Identities) != 3 {
		t.Fatalf("expected 3 identities, got: %d", len(u.Identities))
	}

	if len(u.Bundle.X509Authorities()) != 1 {
		t.Fatal("expected 1 bundle root CA")
	}

	if !u.Bundle.Equal(api.bundle) {
		t.Fatal("received bundle should be equals to the server bundle")
	}

	for key, eu := range identitiesByEntryID(u.Identities) {
		eb, ok := identitiesBefore[key]
		if !ok {
			t.Fatalf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
		}
		require.Equal(t, eb, eu, "identity received does not match identity on cache")
	}

	require.Equal(t, clk.Now(), m.GetLastSync())

	// SVIDs expire after 3 seconds, so we shouldn't expect any updates after
	// 1 second has elapsed.
	clk.Add(time.Second)
	require.NoError(t, m.synchronize(context.Background()))
	select {
	case <-sub.Updates():
		t.Fatal("update unexpected after 1 second")
	default:
	}

	// After advancing another second, the SVIDs should have been refreshed,
	// since the half-time has been exceeded.
	clk.Add(time.Second)
	require.NoError(t, m.synchronize(context.Background()))
	select {
	case u = <-sub.Updates():
	default:
		t.Fatal("update expected after 2 seconds")
	}

	// Make sure the update contains the updated entries and that the cache
	// has a consistent view.
	identitiesAfter := identitiesByEntryID(m.cache.Identities())
	if len(identitiesAfter) != 3 {
		t.Fatalf("expected 3 identities, got: %d", len(identitiesAfter))
	}

	for key, eb := range identitiesBefore {
		ea, ok := identitiesAfter[key]
		if !ok {
			t.Fatalf("expected identity with EntryId=%v after synchronization", key)
		}
		require.NotEqual(t, eb, ea, "there is at least one identity that was not refreshed: %v", ea)
	}

	if len(u.Identities) != 3 {
		t.Fatalf("expected 3 identities, got: %d", len(u.Identities))
	}

	if len(u.Bundle.X509Authorities()) != 1 {
		t.Fatal("expected 1 bundle root CA")
	}

	if !u.Bundle.Equal(api.bundle) {
		t.Fatal("received bundle should be equals to the server bundle")
	}

	for key, eu := range identitiesByEntryID(u.Identities) {
		ea, ok := identitiesAfter[key]
		if !ok {
			t.Fatalf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
		}
		require.Equal(t, eu, ea, "entry received does not match entry on cache")
	}

	require.Equal(t, clk.Now(), m.GetLastSync())
}

func TestSyncRetriesWithDefaultIntervalOnZeroSVIDSReturned(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	startAt := time.Now()
	clk := clock.NewMockAt(t, startAt)
	actualSyncIntervals := []time.Duration{}
	clk.SetAfterHook(func(d time.Duration) <-chan time.Time {
		actualSyncIntervals = append(actualSyncIntervals, d)
		c := make(chan time.Time, 1)
		c <- startAt.Add(time.Second)
		return c
	})
	timeout := time.Second * 10
	getAuthorizedEntriesAttempts := 0

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(*mockAPI, int32, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			// simulate 2 consecutive cache misses in server
			getAuthorizedEntriesAttempts++
			if getAuthorizedEntriesAttempts < 3 {
				return &entryv1.GetAuthorizedEntriesResponse{
					Entries: []*types.Entry{},
				}, nil
			}
			// stop the sync loop with returning the entries because we will now wait for the long 'SyncInterval'
			cancel()
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		svidTTL: 100,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	sto := openStorage(t, dir)
	ts := &trustbundlesources.Config{
		InsecureBootstrap:     false,
		TrustBundleFormat:     "pem",
		TrustBundlePath:       "",
		TrustBundleURL:        "",
		TrustBundleUnixSocket: "",
		TrustDomain:           "example.org",
		ServerAddress:         "localhost",
		ServerPort:            1234,
	}

	tbs := trustbundlesources.New(ts, nil)
	tbs.SetMetrics(&telemetry.Blackhole{})
	err := tbs.SetStorage(sto)
	require.NoError(t, err)

	c := &Config{
		ServerAddr:         api.addr,
		SVID:               baseSVID,
		SVIDKey:            baseSVIDKey,
		Log:                testLogger,
		TrustDomain:        trustDomain,
		TrustBundleSources: tbs,
		Storage:            sto,
		Bundle:             api.bundle,
		Metrics:            &telemetry.Blackhole{},
		RotationInterval:   time.Hour,
		// set sync interval to a high value to proof that synchronizer retries sync
		// with the lower default interval in case 0 entries are returned
		SyncInterval:     time.Hour,
		Clk:              clk,
		Catalog:          cat,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)

	// initialize generates the first attempt at fetching entries
	if err := m.Initialize(ctx); err != nil {
		t.Fatal(err)
	}

	if err := m.runSynchronizer(ctx); err != nil {
		t.Fatal(err)
	}

	// m.runSynchronizer should fetch the entries 2 more times, totalling 3 attempts
	if getAuthorizedEntriesAttempts != 3 {
		t.Fatalf("did not attempt to fetch entries 3 times; attempts: %d", getAuthorizedEntriesAttempts)
	}

	// m.runSynchronizer should sync 2 times with the faster "defaultSyncInterval" after no entries are returned
	if (actualSyncIntervals[0] != defaultSyncInterval) || (actualSyncIntervals[1] != defaultSyncInterval) {
		t.Fatalf("did not do a fast sync retry after 0 SVIDs were returned; sync intervals: %v", actualSyncIntervals)
	}
}

func TestSyncFailsWithUnknownAuthority(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	// Create a verification error
	ca := testca.New(t, spiffeid.RequireTrustDomainFromString("test.td"))
	ca2 := testca.New(t, spiffeid.RequireTrustDomainFromString("test.td"))
	svid := ca2.CreateX509SVID(spiffeid.RequireFromString("spiffe://test.td/w1"))
	_, _, unknownAuthorityErr := x509svid.Verify(svid.Certificates, ca.X509Bundle())
	require.Error(t, unknownAuthorityErr)

	startAt := time.Now()
	clk := clock.NewMockAt(t, startAt)
	actualSyncIntervals := []time.Duration{}
	clk.SetAfterHook(func(d time.Duration) <-chan time.Time {
		actualSyncIntervals = append(actualSyncIntervals, d)
		c := make(chan time.Time, 1)
		c <- startAt.Add(time.Second)
		return c
	})
	timeout := time.Second * 10
	getAuthorizedEntriesAttempts := 0

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(*mockAPI, int32, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			getAuthorizedEntriesAttempts++
			if getAuthorizedEntriesAttempts > 1 {
				return nil, unknownAuthorityErr
			}
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		svidTTL: 100,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	sto := openStorage(t, dir)
	ts := &trustbundlesources.Config{
		InsecureBootstrap:     false,
		TrustBundleFormat:     "pem",
		TrustBundlePath:       "",
		TrustBundleURL:        "",
		TrustBundleUnixSocket: "",
		TrustDomain:           "example.org",
		ServerAddress:         "localhost",
		ServerPort:            1234,
	}

	tbs := trustbundlesources.New(ts, nil)
	tbs.SetMetrics(&telemetry.Blackhole{})
	err := tbs.SetStorage(sto)
	require.NoError(t, err)

	rebootstrapDelay, _ := time.ParseDuration("10m")
	c := &Config{
		ServerAddr:         api.addr,
		SVID:               baseSVID,
		SVIDKey:            baseSVIDKey,
		Log:                testLogger,
		TrustDomain:        trustDomain,
		TrustBundleSources: tbs,
		RebootstrapMode:    "never",
		RebootstrapDelay:   rebootstrapDelay,
		Storage:            sto,
		Bundle:             api.bundle,
		Metrics:            &telemetry.Blackhole{},
		RotationInterval:   time.Hour,
		// set sync interval to a high value to proof that synchronizer retries sync
		// with the lower default interval in case 0 entries are returned
		SyncInterval:     time.Hour,
		Clk:              clk,
		Catalog:          cat,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)

	// initialize generates the first attempt at fetching entries
	if err := m.Initialize(ctx); err != nil {
		t.Fatal(err)
	}

	/// Sync to get expected error
	err = m.runSynchronizer(ctx)
	spiretest.RequireErrorPrefix(t, err, "failed to sync with SPIRE Server:")
}

func TestSyncSVIDsWithLRUCache(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(h *mockAPI, count int32, _ *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			switch count {
			case 1:
				return makeGetAuthorizedEntriesResponse(t, "resp2"), nil
			case 2:
				return makeGetAuthorizedEntriesResponse(t, "resp2"), nil
			default:
				return nil, fmt.Errorf("unexpected getAuthorizedEntries call count: %d", count)
			}
		},
		batchNewX509SVIDEntries: func(h *mockAPI, count int32) []*common.RegistrationEntry {
			switch count {
			case 1:
				return makeBatchNewX509SVIDEntries("resp2")
			case 2:
				return makeBatchNewX509SVIDEntries("resp2")
			default:
				return nil
			}
		},
		svidTTL: 3,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	c := &Config{
		ServerAddr:           api.addr,
		SVID:                 baseSVID,
		SVIDKey:              baseSVIDKey,
		Log:                  testLogger,
		TrustDomain:          trustDomain,
		Storage:              openStorage(t, dir),
		Bundle:               api.bundle,
		Metrics:              &telemetry.Blackhole{},
		Clk:                  clk,
		Catalog:              cat,
		WorkloadKeyType:      workloadkey.ECP256,
		X509SVIDCacheMaxSize: 1,
		JWTSVIDCacheMaxSize:  1,
		SVIDStoreCache:       storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy:     rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)

	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	subErrCh := make(chan error, 1)
	go func(ctx context.Context) {
		sub, err := m.SubscribeToCacheChanges(ctx, cache.Selectors{
			{Type: "unix", Value: "uid:1111"},
		})
		if err != nil {
			subErrCh <- err
			return
		}
		defer sub.Finish()
		subErrCh <- nil
	}(ctx)

	syncErrCh := make(chan error, 1)
	// run svid sync
	go func(ctx context.Context) {
		syncErrCh <- m.runSyncSVIDs(ctx)
	}(ctx)

	// keep clk moving so that subscriber keeps looking for svid
	go func(ctx context.Context) {
		for {
			clk.Add(cache.SVIDSyncInterval)
			if ctx.Err() != nil {
				return
			}
		}
	}(ctx)

	subErr := <-subErrCh
	assert.NoError(t, subErr, "subscriber error")

	// ensure 2 SVIDs corresponding to selectors are cached.
	assert.Equal(t, 2, m.cache.CountX509SVIDs())

	// cancel the ctx to stop Go routines
	cancel()

	syncErr := <-syncErrCh
	assert.NoError(t, syncErr, "svid sync error")
}

func TestSurvivesCARotation(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	ttlSeconds := 3
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(h *mockAPI, count int32, req *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(h *mockAPI, count int32) []*common.RegistrationEntry {
			h.rotateCA()
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		clk: clk,
		// Give a low ttl to get expired entries on each synchronization, forcing
		// the manager to fetch entries from the server.
		svidTTL: ttlSeconds,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	ttl := time.Duration(ttlSeconds) * time.Second
	syncInterval := ttl / 2
	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: 1 * time.Hour,
		SyncInterval:     syncInterval,
		Clk:              clk,
		Catalog:          cat,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)

	sub, err := m.SubscribeToCacheChanges(context.Background(), cache.Selectors{{Type: "unix", Value: "uid:1111"}})
	require.NoError(t, err)
	// This should be the update received when Subscribe function was called.
	updates := sub.Updates()
	initialUpdate := <-updates
	initialRoot := initialUpdate.Bundle.X509Authorities()[0]

	defer initializeAndRunManager(t, m)()

	// Second FetchX509 request will create a new CA
	clk.Add(syncInterval)
	newCAUpdate := <-updates
	newRoots := newCAUpdate.Bundle.X509Authorities()
	require.Contains(t, newRoots, initialRoot)
	require.Len(t, newRoots, 2)
}

func TestFetchJWTSVID(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	fetchResp := &svidv1.NewJWTSVIDResponse{}

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(*mockAPI, int32, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		newJWTSVID: func(*mockAPI, *svidv1.NewJWTSVIDRequest) (*svidv1.NewJWTSVIDResponse, error) {
			return fetchResp, nil
		},
		clk:     clk,
		svidTTL: 200,
	})

	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		Catalog:          cat,
		Clk:              clk,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)
	require.NoError(t, m.Initialize(context.Background()))

	audience := []string{"foo"}

	// nothing in cache, fetch fails
	svid, err := m.FetchJWTSVID(context.Background(), regEntriesMap["resp2"][0], audience)
	require.Error(t, err)
	require.Empty(t, svid)

	now := clk.Now()
	// fetch succeeds
	tokenA := "A"
	issuedAtA := now.Unix()
	expiresAtA := now.Add(time.Minute).Unix()
	fetchResp.Svid = &types.JWTSVID{
		Token:     tokenA,
		IssuedAt:  issuedAtA,
		ExpiresAt: expiresAtA,
	}
	svid, err = m.FetchJWTSVID(context.Background(), regEntriesMap["resp2"][0], audience)
	require.NoError(t, err)
	require.Equal(t, tokenA, svid.Token)
	require.Equal(t, issuedAtA, svid.IssuedAt.Unix())
	require.Equal(t, expiresAtA, svid.ExpiresAt.Unix())

	// assert cached JWT is returned w/o trying to fetch (since cached version does not expire soon)
	fetchResp.Svid = &types.JWTSVID{
		Token:     "B",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}
	svid, err = m.FetchJWTSVID(context.Background(), regEntriesMap["resp2"][0], audience)
	require.NoError(t, err)
	require.Equal(t, tokenA, svid.Token)
	require.Equal(t, issuedAtA, svid.IssuedAt.Unix())
	require.Equal(t, expiresAtA, svid.ExpiresAt.Unix())

	// expire the cached JWT soon and make sure new JWT is fetched
	clk.Add(time.Second * 45)
	now = clk.Now()
	tokenC := "C"
	issuedAtC := now.Unix()
	expiresAtC := now.Add(time.Minute).Unix()
	fetchResp.Svid = &types.JWTSVID{
		Token:     tokenC,
		IssuedAt:  issuedAtC,
		ExpiresAt: expiresAtC,
	}
	svid, err = m.FetchJWTSVID(context.Background(), regEntriesMap["resp2"][0], audience)
	require.NoError(t, err)
	require.Equal(t, tokenC, svid.Token)
	require.Equal(t, issuedAtC, svid.IssuedAt.Unix())
	require.Equal(t, expiresAtC, svid.ExpiresAt.Unix())

	// expire the JWT soon, fail the fetch, and make sure cached JWT is returned
	clk.Add(time.Second * 30)
	fetchResp.Svid = nil
	svid, err = m.FetchJWTSVID(context.Background(), regEntriesMap["resp2"][0], audience)
	require.NoError(t, err)
	require.Equal(t, tokenC, svid.Token)
	require.Equal(t, issuedAtC, svid.IssuedAt.Unix())
	require.Equal(t, expiresAtC, svid.ExpiresAt.Unix())

	// now completely expire the JWT and make sure an error is returned, since
	// the fetch fails and the cached version is expired.
	clk.Add(time.Second * 30)
	svid, err = m.FetchJWTSVID(context.Background(), regEntriesMap["resp2"][0], audience)
	require.Error(t, err)
	require.Nil(t, svid)
}

func TestStorableSVIDsSync(t *testing.T) {
	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(h *mockAPI, count int32, req *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			switch count {
			case 1:
				return makeGetAuthorizedEntriesResponse(t, "resp2", "resp4"), nil
			case 2:
				return makeGetAuthorizedEntriesResponse(t, "resp2", "resp5"), nil
			default:
				return nil, fmt.Errorf("unexpected getAuthorizedEntries call count: %d", count)
			}
		},
		batchNewX509SVIDEntries: func(h *mockAPI, count int32) []*common.RegistrationEntry {
			switch count {
			case 1:
				return makeBatchNewX509SVIDEntries("resp2", "resp4")
			case 2:
				return makeBatchNewX509SVIDEntries("resp2", "resp5")
			default:
				return nil
			}
		},
		svidTTL: 200,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentkeymanager.New(t, dir))

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		Clk:              clk,
		Catalog:          cat,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m, closer := initializeAndRunNewManager(t, c)
	defer closer()

	validateResponse := func(records []*storecache.Record, entries []*common.RegistrationEntry) {
		require.NotEmpty(t, entries)
		require.Len(t, records, len(entries))

		// Expected entries, and verify that SVIDs is up to date
		for i, record := range records {
			require.Len(t, records, len(entries))
			spiretest.RequireProtoEqual(t, entries[i], record.Entry)

			// Verify record has latest's SVIDs
			chain := api.lastestSVIDs[record.Entry.EntryId]
			require.Equal(t, chain, record.Svid.Chain)
		}
	}

	// Fist call will take resp4 and create SVIDs since it is the first call
	entries := regEntriesMap["resp4"]
	records := m.svidStoreCache.Records()
	validateResponse(records, entries)

	// manually synchronize again
	if err := m.synchronize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Second call will take resp5 and update SVID, this tests is not testing the process to update cache
	// but that is updating based on sync
	entries = regEntriesMap["resp5"]
	records = m.svidStoreCache.Records()
	validateResponse(records, entries)
}

func makeGetAuthorizedEntriesResponse(t *testing.T, respKeys ...string) *entryv1.GetAuthorizedEntriesResponse {
	var entries []*types.Entry
	for _, respKey := range respKeys {
		for _, regEntry := range regEntriesMap[respKey] {
			// Only some of the fields are populated by the client
			spiffeID, err := spiffeid.FromString(regEntry.SpiffeId)
			require.NoError(t, err)
			entries = append(entries, &types.Entry{
				Id:             regEntry.EntryId,
				SpiffeId:       api.ProtoFromID(spiffeID),
				FederatesWith:  regEntry.FederatesWith,
				RevisionNumber: regEntry.RevisionNumber,
				Selectors:      api.ProtoFromSelectors(regEntry.Selectors),
				StoreSvid:      regEntry.StoreSvid,
			})
		}
	}

	return &entryv1.GetAuthorizedEntriesResponse{
		Entries: entries,
	}
}

func makeBatchNewX509SVIDEntries(regEntryKeys ...string) []*common.RegistrationEntry {
	var regEntries []*common.RegistrationEntry
	for _, regEntryKey := range regEntryKeys {
		regEntries = append(regEntries, regEntriesMap[regEntryKey]...)
	}

	return regEntries
}

func regEntriesAsMap(res []*common.RegistrationEntry) (result map[string]*common.RegistrationEntry) {
	result = map[string]*common.RegistrationEntry{}
	for _, re := range res {
		result[re.EntryId] = re
	}
	return result
}

func identitiesByEntryID(ces []cache.Identity) (result map[string]cache.Identity) {
	result = map[string]cache.Identity{}
	for _, ce := range ces {
		result[ce.Entry.EntryId] = ce
	}
	return result
}

func compareRegistrationEntries(t *testing.T, expected, actual []*common.RegistrationEntry) {
	if len(expected) != len(actual) {
		t.Fatalf("entries count doesn't match, expected: %d, got: %d", len(expected), len(actual))
	}

	expectedMap := regEntriesAsMap(expected)
	actualMap := regEntriesAsMap(actual)

	for id, ee := range expectedMap {
		ae, ok := actualMap[id]
		if !ok {
			t.Fatalf("entries should be equals, expected: %s, got: <none>", ee.String())
		}

		if ee.String() != ae.String() {
			t.Fatalf("entries should be equals, expected: %s, got: %s", ee.String(), ae.String())
		}
	}
}

type mockAPIConfig struct {
	km                      keymanager.KeyManager
	getAuthorizedEntries    func(api *mockAPI, count int32, req *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error)
	batchNewX509SVIDEntries func(api *mockAPI, count int32) []*common.RegistrationEntry
	newJWTSVID              func(api *mockAPI, req *svidv1.NewJWTSVIDRequest) (*svidv1.NewJWTSVIDResponse, error)

	svidTTL int
	clk     clock.Clock
}

type mockAPI struct {
	t *testing.T
	c *mockAPIConfig

	addr string

	bundle *spiffebundle.Bundle
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey

	svid []*x509.Certificate

	// Counts the number of requests received from clients
	getAuthorizedEntriesCount int32
	batchNewX509SVIDCount     int32

	taintedX509Authority *x509.Certificate

	clk clock.Clock

	// Add latest's SVIDs per entry, to verify returned SVIDs are valid
	lastestSVIDs map[string][]*x509.Certificate

	agentv1.UnimplementedAgentServer
	bundlev1.UnimplementedBundleServer
	entryv1.UnimplementedEntryServer
	svidv1.UnimplementedSVIDServer
}

func newMockAPI(t *testing.T, config *mockAPIConfig) *mockAPI {
	bundle := spiffebundle.New(trustDomain)
	bundle.SetRefreshHint(0)
	bundle.SetSequenceNumber(0)
	h := &mockAPI{
		t:            t,
		c:            config,
		bundle:       bundle,
		clk:          config.clk,
		lastestSVIDs: make(map[string][]*x509.Certificate),
	}

	h.rotateCA()

	serverID := idutil.RequireServerID(trustDomain)
	h.svid = createSVIDWithKey(t, config.clk, h.ca, h.caKey, serverID, time.Hour, serverKey)

	tlsConfig := &tls.Config{
		GetConfigForClient: h.getGRPCServerConfig,
		MinVersion:         tls.VersionTLS12,
	}

	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	agentv1.RegisterAgentServer(server, h)
	bundlev1.RegisterBundleServer(server, h)
	entryv1.RegisterEntryServer(server, h)
	svidv1.RegisterSVIDServer(server, h)

	listener, err := net.Listen("tcp", "localhost:")
	require.NoError(t, err)
	h.addr = listener.Addr().String()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
		if err != nil {
			panic(fmt.Errorf("error starting mock server: %w", err))
		}
	}()

	t.Cleanup(func() {
		server.Stop()
		assert.NoError(t, <-errCh)
	})

	return h
}

func (h *mockAPI) RenewAgent(ctx context.Context, req *agentv1.RenewAgentRequest) (*agentv1.RenewAgentResponse, error) {
	agentSVID, _ := h.getCertFromCtx(ctx)
	agentID, _ := x509svid.IDFromCert(agentSVID)
	svid := h.newSVIDFromCSR(agentID, req.Params.Csr)
	return &agentv1.RenewAgentResponse{
		Svid: &types.X509SVID{
			CertChain: x509util.RawCertsFromCertificates(svid),
			ExpiresAt: svid[0].NotAfter.Unix(),
		},
	}, nil
}

func (h *mockAPI) GetAuthorizedEntries(_ context.Context, req *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
	count := atomic.AddInt32(&h.getAuthorizedEntriesCount, 1)
	if h.c.getAuthorizedEntries != nil {
		return h.c.getAuthorizedEntries(h, count, req)
	}
	return nil, errors.New("no GetAuthorizedEntries implementation for test")
}

func (h *mockAPI) BatchNewX509SVID(_ context.Context, req *svidv1.BatchNewX509SVIDRequest) (*svidv1.BatchNewX509SVIDResponse, error) {
	count := atomic.AddInt32(&h.batchNewX509SVIDCount, 1)

	var entries map[string]*common.RegistrationEntry
	if h.c.batchNewX509SVIDEntries != nil {
		entries = regEntriesAsMap(h.c.batchNewX509SVIDEntries(h, count))
	}
	resp := new(svidv1.BatchNewX509SVIDResponse)
	for _, param := range req.Params {
		entry, ok := entries[param.EntryId]
		if !ok {
			resp.Results = append(resp.Results, &svidv1.BatchNewX509SVIDResponse_Result{
				Status: api.CreateStatusf(codes.NotFound, "entry %q not found", param.EntryId),
			})
			continue
		}
		svid := h.newSVIDFromCSR(spiffeid.RequireFromString(entry.SpiffeId), param.Csr)

		// Keep latest's SVIDs per entry
		h.lastestSVIDs[entry.EntryId] = svid

		resp.Results = append(resp.Results, &svidv1.BatchNewX509SVIDResponse_Result{
			Status: api.OK(),
			Svid: &types.X509SVID{
				CertChain: x509util.RawCertsFromCertificates(svid),
				ExpiresAt: svid[0].NotAfter.Unix(),
			},
		})
	}
	return resp, nil
}

func (h *mockAPI) NewJWTSVID(_ context.Context, req *svidv1.NewJWTSVIDRequest) (*svidv1.NewJWTSVIDResponse, error) {
	if h.c.newJWTSVID != nil {
		return h.c.newJWTSVID(h, req)
	}
	return nil, errors.New("no FetchJWTSVID implementation for test")
}

func (h *mockAPI) GetBundle(context.Context, *bundlev1.GetBundleRequest) (*types.Bundle, error) {
	bundle := bundleutil.BundleProtoFromRootCAs(h.bundle.TrustDomain().IDString(), h.bundle.X509Authorities())
	if h.taintedX509Authority != nil {
		for _, eachRootCA := range bundle.RootCas {
			if reflect.DeepEqual(eachRootCA.DerBytes, h.taintedX509Authority.Raw) {
				eachRootCA.TaintedKey = true
			}
		}
	}

	return api.BundleToProto(bundle)
}

func (h *mockAPI) GetFederatedBundle(_ context.Context, req *bundlev1.GetFederatedBundleRequest) (*types.Bundle, error) {
	return &types.Bundle{
		TrustDomain: req.TrustDomain,
		X509Authorities: []*types.X509Certificate{
			{Asn1: h.ca.Raw},
		},
	}, nil
}

// taintCurrentX509Authority create a new X.509 authority and taint old
func (h *mockAPI) taintCurrentX509Authority() {
	h.taintedX509Authority = h.ca
	ca, caKey := createCA(h.t, h.clk)
	h.ca = ca
	h.caKey = caKey
	h.bundle.AddX509Authority(ca)
}

func (h *mockAPI) rotateCA() {
	ca, caKey := createCA(h.t, h.clk)
	h.ca = ca
	h.caKey = caKey
	h.bundle.AddX509Authority(ca)
}

func (h *mockAPI) newSVID(spiffeID spiffeid.ID, ttl time.Duration) ([]*x509.Certificate, keymanager.Key) {
	return createSVID(h.t, h.c.km, h.clk, h.ca, h.caKey, spiffeID, ttl)
}

func (h *mockAPI) newSVIDFromCSR(spiffeID spiffeid.ID, csr []byte) []*x509.Certificate {
	return createSVIDFromCSR(h.t, h.clk, h.ca, h.caKey, spiffeID, csr, h.c.svidTTL)
}

func (h *mockAPI) getGRPCServerConfig(*tls.ClientHelloInfo) (*tls.Config, error) {
	certChain := [][]byte{}
	for _, c := range h.svid {
		certChain = append(certChain, c.Raw)
	}
	certChain = append(certChain, h.ca.Raw)
	certs := []tls.Certificate{{
		Certificate: certChain,
		PrivateKey:  serverKey,
	}}

	roots := x509.NewCertPool()
	roots.AddCert(h.ca)

	return &tls.Config{
		ClientAuth:   tls.VerifyClientCertIfGiven,
		Certificates: certs,
		ClientCAs:    roots,
		MinVersion:   tls.VersionTLS12,
		NextProtos: []string{
			"h2",
		},
	}, nil
}

func (h *mockAPI) getCertFromCtx(ctx context.Context) (certificate *x509.Certificate, err error) {
	ctxPeer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("no peer information")
	}
	tlsInfo, ok := ctxPeer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.New("no TLS auth info for peer")
	}

	if len(tlsInfo.State.VerifiedChains) == 0 {
		return nil, errors.New("no verified client certificate presented by peer")
	}
	chain := tlsInfo.State.VerifiedChains[0]
	if len(chain) == 0 {
		// this shouldn't be possible with the tls package, but we should be
		// defensive.
		return nil, errors.New("verified client chain is missing certificates")
	}

	return chain[0], nil
}

func createCA(t *testing.T, clk clock.Clock) (*x509.Certificate, *ecdsa.PrivateKey) {
	tmpl, err := util.NewCATemplate(clk, trustDomain)
	if err != nil {
		t.Fatalf("cannot create ca template: %v", err)
	}

	ca, caKey, err := util.SelfSign(tmpl)
	if err != nil {
		t.Fatalf("cannot self sign ca template: %v", err)
	}
	return ca, caKey
}

func createSVID(t *testing.T, km keymanager.KeyManager, clk clock.Clock, ca *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID spiffeid.ID, ttl time.Duration) ([]*x509.Certificate, keymanager.Key) {
	svidKey, err := keymanager.ForSVID(km).GenerateKey(context.Background(), nil)
	require.NoError(t, err)

	return createSVIDWithKey(t, clk, ca, caKey, spiffeID, ttl, svidKey), svidKey
}

func createSVIDWithKey(t *testing.T, clk clock.Clock, ca *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID spiffeid.ID, ttl time.Duration, svidKey crypto.Signer) []*x509.Certificate {
	tmpl, err := util.NewSVIDTemplate(clk, spiffeID.String())
	require.NoError(t, err)

	tmpl.NotAfter = tmpl.NotBefore.Add(ttl)
	tmpl.PublicKey = svidKey.Public()

	svid, _, err := util.Sign(tmpl, ca, caKey)
	require.NoError(t, err)

	return []*x509.Certificate{svid}
}

func createSVIDFromCSR(t *testing.T, clk clock.Clock, ca *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeID spiffeid.ID, csr []byte, ttl int) []*x509.Certificate {
	req, err := x509.ParseCertificateRequest(csr)
	require.NoError(t, err)

	tmpl, err := util.NewSVIDTemplate(clk, spiffeID.String())
	require.NoError(t, err)
	tmpl.PublicKey = req.PublicKey
	tmpl.NotAfter = tmpl.NotBefore.Add(time.Duration(ttl) * time.Second)

	svid, _, err := util.Sign(tmpl, ca, caKey)
	require.NoError(t, err)

	return []*x509.Certificate{svid}
}

func initializeNewManager(t *testing.T, c *Config) *manager {
	m := newManager(c)
	require.NoError(t, m.Initialize(context.Background()))
	return m
}

func initializeAndRunNewManager(t *testing.T, c *Config) (*manager, func()) {
	m := initializeNewManager(t, c)
	return m, runManager(t, m)
}

func initializeAndRunManager(t *testing.T, m *manager) (closer func()) {
	require.NoError(t, m.Initialize(context.Background()))
	return runManager(t, m)
}

func runManager(t *testing.T, m *manager) (closer func()) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := m.Run(ctx); err != nil {
			t.Error(err)
		}
	}()
	return func() {
		cancel()
		wg.Wait()
	}
}

func svidsEqual(as, bs []*x509.Certificate) bool {
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if !as[i].Equal(bs[i]) {
			return false
		}
	}
	return true
}

func openStorage(t *testing.T, dir string) storage.Storage {
	sto, err := storage.Open(dir)
	require.NoError(t, err)
	return sto
}
