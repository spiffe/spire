package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"path"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	testlog "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/disk"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/memory"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	agentv1 "github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire/proto/spire/api/server/bundle/v1"
	entryv1 "github.com/spiffe/spire/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/types"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var (
	trustDomain    = spiffeid.RequireTrustDomainFromString("example.org")
	trustDomainURL = *trustDomain.ID().URL()
	agentID        = trustDomain.NewID("agent")
	joinTokenID    = trustDomain.NewID("spire/agent/join_token/abcd")
)

var (
	testLogger, _ = testlog.NewNullLogger()
	regEntriesMap = util.GetRegistrationEntriesMap("manager_test_entries.json")
)

func TestInitializationFailure(t *testing.T) {
	dir := spiretest.TempDir(t)

	clk := clock.NewMock(t)
	ca, cakey := createCA(t, clk)
	baseSVID, baseSVIDKey := createSVID(t, clk, ca, cakey, agentID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(memory.New()))

	c := &Config{
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		Metrics:         &telemetry.Blackhole{},
		TrustDomain:     trustDomainURL,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Clk:             clk,
		Catalog:         cat,
	}
	m := newManager(c)
	require.Error(t, m.Initialize(context.Background()))
}

func TestStoreBundleOnStartup(t *testing.T) {
	dir := spiretest.TempDir(t)

	clk := clock.NewMock(t)
	ca, cakey := createCA(t, clk)
	baseSVID, baseSVIDKey := createSVID(t, clk, ca, cakey, agentID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	km := disk.New()
	_, err := km.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: fmt.Sprintf(`directory = %q`, dir),
	})
	if err != nil {
		t.Fatal(err)
	}
	cat.SetKeyManager(fakeagentcatalog.KeyManager(km))

	c := &Config{
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		Metrics:         &telemetry.Blackhole{},
		TrustDomain:     trustDomainURL,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          bundleutil.BundleFromRootCA(trustDomain.IDString(), ca),
		Clk:             clk,
		Catalog:         cat,
	}

	m := newManager(c)

	util.RunWithTimeout(t, time.Second, func() {
		sub := m.SubscribeToBundleChanges()
		bundles := sub.Value()
		require.NotNil(t, bundles)
		bundle := bundles[trustDomain.IDString()]
		require.Equal(t, bundle.RootCAs(), []*x509.Certificate{ca})
	})

	require.Error(t, m.Initialize(context.Background()))

	// Although init failed, the bundle should have been saved, because it should be
	// one of the first thing the manager does at initialization.
	bundle, err := ReadBundle(c.BundleCachePath)
	if err != nil {
		t.Fatalf("bundle should have been saved in a file: %v", err)
	}

	if !bundle[0].Equal(ca) {
		t.Fatal("bundle should have included CA certificate")
	}
}

func TestStoreSVIDOnStartup(t *testing.T) {
	dir := spiretest.TempDir(t)

	clk := clock.NewMock(t)
	ca, cakey := createCA(t, clk)
	baseSVID, baseSVIDKey := createSVID(t, clk, ca, cakey, agentID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	km := disk.New()
	_, err := km.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: fmt.Sprintf(`directory = %q`, dir),
	})
	if err != nil {
		t.Fatal(err)
	}
	cat.SetKeyManager(fakeagentcatalog.KeyManager(km))

	c := &Config{
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		Metrics:         &telemetry.Blackhole{},
		TrustDomain:     trustDomainURL,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Clk:             clk,
		Catalog:         cat,
	}

	_, err = ReadSVID(c.SVIDCachePath)
	if err != ErrNotCached {
		t.Fatalf("wanted: %v, got: %v", ErrNotCached, err)
	}

	m := newManager(c)

	err = m.Initialize(context.Background())
	if err == nil {
		t.Fatal("manager was expected to fail during initialization")
	}

	// Although start failed, the SVID should have been saved, because it should be
	// one of the first thing the manager does at initialization.
	svid, err := ReadSVID(c.SVIDCachePath)
	if err != nil {
		t.Fatal(err)
	}
	if !svidsEqual(svid, baseSVID) {
		t.Fatal("SVID was not correctly stored.")
	}
}

func TestStoreKeyOnStartup(t *testing.T) {
	dir := spiretest.TempDir(t)

	clk := clock.NewMock(t)
	ca, cakey := createCA(t, clk)
	baseSVID, baseSVIDKey := createSVID(t, clk, ca, cakey, agentID, 1*time.Hour)

	cat := fakeagentcatalog.New()
	diskPlugin := disk.New()
	_, err := diskPlugin.Configure(context.Background(), &plugin.ConfigureRequest{Configuration: fmt.Sprintf("directory = \"%s\"", dir)})
	require.NoError(t, err)
	cat.SetKeyManager(fakeagentcatalog.KeyManager(diskPlugin))

	c := &Config{
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		Metrics:         &telemetry.Blackhole{},
		TrustDomain:     trustDomainURL,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Clk:             clk,
		Catalog:         cat,
	}

	km := cat.GetKeyManager()
	kresp, err := km.FetchPrivateKey(context.Background(), &keymanager.FetchPrivateKeyRequest{})
	if err != nil {
		t.Fatalf("No error expected but got: %v", err)
	}
	if len(kresp.PrivateKey) != 0 {
		t.Fatalf("No key expected but got: %v", kresp.PrivateKey)
	}

	m := newManager(c)
	require.Error(t, m.Initialize(context.Background()))

	// Although init failed, the SVID key should have been saved, because it should be
	// one of the first thing the manager does at initialization.
	kresp, err = km.FetchPrivateKey(context.Background(), &keymanager.FetchPrivateKeyRequest{})
	if err != nil {
		t.Fatalf("No error expected but got: %v", err)
	}

	storedKey, err := x509.ParseECPrivateKey(kresp.PrivateKey)
	if err != nil {
		t.Fatalf("No error expected but got: %v", err)
	}

	if !reflect.DeepEqual(storedKey, baseSVIDKey) {
		t.Fatal("stored key is different than provided")
	}
}

func TestHappyPathWithoutSyncNorRotation(t *testing.T) {
	dir := spiretest.TempDir(t)

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
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
	km := disk.New()

	_, err := km.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: fmt.Sprintf(`directory = %q`, dir),
	})
	require.NoError(t, err)

	cat.SetKeyManager(fakeagentcatalog.KeyManager(km))

	c := &Config{
		ServerAddr:      api.addr,
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     trustDomainURL,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          api.bundle,
		Metrics:         &telemetry.Blackhole{},
		Clk:             clk,
		Catalog:         cat,
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

	matches := m.MatchingIdentities(cache.Selectors{{Type: "unix", Value: "uid:1111"}})
	if len(matches) != 2 {
		t.Fatal("expected 2 identities")
	}

	// Verify bundle
	require.Equal(t, api.bundle, m.GetBundle())

	// Expect three SVIDs on cache
	require.Equal(t, 3, m.CountSVIDs())

	// Expect last sync
	require.Equal(t, clk.Now(), m.GetLastSync())

	compareRegistrationEntries(t,
		regEntriesMap["resp2"],
		[]*common.RegistrationEntry{matches[0].Entry, matches[1].Entry})

	util.RunWithTimeout(t, 5*time.Second, func() {
		sub := m.SubscribeToCacheChanges(cache.Selectors{{Type: "unix", Value: "uid:1111"}})
		u := <-sub.Updates()

		if len(u.Identities) != 2 {
			t.Fatal("expected 2 entries")
		}

		if len(u.Bundle.RootCAs()) != 1 {
			t.Fatal("expected 1 bundle root CA")
		}

		if !u.Bundle.EqualTo(api.bundle) {
			t.Fatal("received bundle should be equals to the server bundle")
		}

		compareRegistrationEntries(t,
			regEntriesMap["resp2"],
			[]*common.RegistrationEntry{u.Identities[0].Entry, u.Identities[1].Entry})
	})
}

func TestSVIDRotation(t *testing.T) {
	dir := spiretest.TempDir(t)

	clk := clock.NewMock(t)

	baseTTL := 3
	api := newMockAPI(t, &mockAPIConfig{
		getAuthorizedEntries: func(*mockAPI, int32, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		svidTTL: baseTTL,
		clk:     clk,
	})

	baseTTLSeconds := time.Duration(baseTTL) * time.Second
	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, baseTTLSeconds)

	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(memory.New()))

	c := &Config{
		Catalog:          cat,
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomainURL,
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: baseTTLSeconds / 2,
		SyncInterval:     1 * time.Hour,
		Clk:              clk,
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

	// now that the ticker is created, cause a tick to happen
	clk.Add(baseTTLSeconds / 2)

	// Loop, we should not detect SVID rotations
	for i := 0; i < 10; i++ {
		s := m.GetCurrentCredentials()
		svid = s.SVID
		require.True(t, svidsEqual(svid, baseSVID))
		require.False(t, wasRotHookCalled())
		clk.Add(100 * time.Millisecond)
	}

	// RUnlock simulates the end of the request (Rotator should rotate SVIDs now)
	m.GetRotationMtx().RUnlock()

	// Loop until we detect an SVID rotation was called in separate process
	util.RunWithTimeout(t, time.Minute, func() {
		for {
			if wasRotHookCalled() {
				break
			}
		}
	})

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

	clk := clock.NewMock(t)
	ttl := 3
	api := newMockAPI(t, &mockAPIConfig{
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
	km := disk.New()
	_, err := km.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: fmt.Sprintf(`directory = %q`, dir),
	})
	require.NoError(t, err)
	cat.SetKeyManager(fakeagentcatalog.KeyManager(km))

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomainURL,
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: time.Hour,
		SyncInterval:     time.Hour,
		Clk:              clk,
		Catalog:          cat,
	}

	m := newManager(c)

	sub := m.SubscribeToCacheChanges(cache.Selectors{
		{Type: "unix", Value: "uid:1111"},
		{Type: "spiffe_id", Value: joinTokenID.String()},
	})
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

	if len(u.Bundle.RootCAs()) != 1 {
		t.Fatal("expected 1 bundle root CA")
	}

	if !u.Bundle.EqualTo(api.bundle) {
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

	if len(u.Bundle.RootCAs()) != 1 {
		t.Fatal("expected 1 bundle root CA")
	}

	if !u.Bundle.EqualTo(api.bundle) {
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

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
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
	km := disk.New()
	_, err := km.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: fmt.Sprintf(`directory = %q`, dir),
	})
	if err != nil {
		t.Fatal(err)
	}
	cat.SetKeyManager(fakeagentcatalog.KeyManager(km))

	c := &Config{
		ServerAddr:      api.addr,
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     trustDomainURL,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          api.bundle,
		Metrics:         &telemetry.Blackhole{},
		Clk:             clk,
		Catalog:         cat,
	}

	m := newManager(c)

	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// after initialization, the cache should contain both resp1 and resp2
	// entries.
	compareRegistrationEntries(t,
		append(regEntriesMap["resp1"], regEntriesMap["resp2"]...),
		regEntriesFromIdentities(m.cache.Identities()))

	// manually synchronize again
	if err := m.synchronize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// now the cache should have entries from resp2 removed
	compareRegistrationEntries(t,
		regEntriesMap["resp1"],
		regEntriesFromIdentities(m.cache.Identities()))
}

func TestSynchronizationUpdatesRegistrationEntries(t *testing.T) {
	dir := spiretest.TempDir(t)

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
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
	km := disk.New()
	_, err := km.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: fmt.Sprintf(`directory = %q`, dir),
	})
	if err != nil {
		t.Fatal(err)
	}
	cat.SetKeyManager(fakeagentcatalog.KeyManager(km))

	c := &Config{
		ServerAddr:      api.addr,
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     trustDomainURL,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          api.bundle,
		Metrics:         &telemetry.Blackhole{},
		Clk:             clk,
		Catalog:         cat,
	}

	m := newManager(c)

	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// after initialization, the cache should contain resp2 entries
	compareRegistrationEntries(t,
		regEntriesMap["resp2"],
		regEntriesFromIdentities(m.cache.Identities()))

	// manually synchronize again
	if err := m.synchronize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// now the cache should have the updated entries from resp3
	compareRegistrationEntries(t,
		regEntriesMap["resp3"],
		regEntriesFromIdentities(m.cache.Identities()))
}

func TestSubscribersGetUpToDateBundle(t *testing.T) {
	dir := spiretest.TempDir(t)

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
		getAuthorizedEntries: func(h *mockAPI, count int32, req *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(h *mockAPI, count int32) []*common.RegistrationEntry {
			ca, _ := createCA(h.t, h.clk)
			h.bundle.AppendRootCA(ca)

			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		svidTTL: 200,
		clk:     clk,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	km := disk.New()
	_, err := km.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: fmt.Sprintf(`directory = %q`, dir),
	})
	require.NoError(t, err)
	cat.SetKeyManager(fakeagentcatalog.KeyManager(km))

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomainURL,
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: 1 * time.Hour,
		SyncInterval:     1 * time.Hour,
		Clk:              clk,
		Catalog:          cat,
	}

	m := newManager(c)

	sub := m.SubscribeToCacheChanges(cache.Selectors{{Type: "unix", Value: "uid:1111"}})

	defer initializeAndRunManager(t, m)()

	util.RunWithTimeout(t, 1*time.Second, func() {
		// Update should contain a new bundle.
		u := <-sub.Updates()
		if len(u.Bundle.RootCAs()) != 2 {
			t.Fatalf("expected 2 bundles, got: %d", len(u.Bundle.RootCAs()))
		}
		if !u.Bundle.EqualTo(c.Bundle) {
			t.Fatal("bundles were expected to be equal")
		}
	})
}

func TestSurvivesCARotation(t *testing.T) {
	dir := spiretest.TempDir(t)

	clk := clock.NewMock(t)
	ttl := 3
	api := newMockAPI(t, &mockAPIConfig{
		getAuthorizedEntries: func(h *mockAPI, count int32, req *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(h *mockAPI, count int32) []*common.RegistrationEntry {
			ca, key := createCA(h.t, h.clk)
			h.cakey = key
			h.bundle.AppendRootCA(ca)

			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		clk: clk,
		// Give a low ttl to get expired entries on each synchronization, forcing
		// the manager to fetch entries from the server.
		svidTTL: ttl,
	})

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)
	cat := fakeagentcatalog.New()
	km := disk.New()
	_, err := km.Configure(context.Background(), &spi.ConfigureRequest{
		Configuration: fmt.Sprintf(`directory = %q`, dir),
	})
	require.NoError(t, err)
	cat.SetKeyManager(fakeagentcatalog.KeyManager(km))

	ttlSeconds := time.Duration(ttl) * time.Second
	syncInterval := ttlSeconds / 2
	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomainURL,
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: 1 * time.Hour,
		SyncInterval:     syncInterval,
		Clk:              clk,
		Catalog:          cat,
	}

	m := newManager(c)

	sub := m.SubscribeToCacheChanges(cache.Selectors{{Type: "unix", Value: "uid:1111"}})
	// This should be the update received when Subscribe function was called.
	updates := sub.Updates()
	initialUpdate := <-updates
	initialRoot := initialUpdate.Bundle.RootCAs()[0]

	defer initializeAndRunManager(t, m)()

	// Second FetchX509 request will create a new CA
	clk.Add(syncInterval)
	newCAUpdate := <-updates
	newRoots := newCAUpdate.Bundle.RootCAs()
	require.Contains(t, newRoots, initialRoot)
	require.Len(t, newRoots, 2)
}

func TestFetchJWTSVID(t *testing.T) {
	dir := spiretest.TempDir(t)

	fetchResp := &svidv1.NewJWTSVIDResponse{}

	clk := clock.NewMock(t)
	api := newMockAPI(t, &mockAPIConfig{
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
	diskPlugin := disk.New()
	_, err := diskPlugin.Configure(context.Background(), &plugin.ConfigureRequest{Configuration: fmt.Sprintf("directory = \"%s\"", dir)})
	require.NoError(t, err)
	cat.SetKeyManager(fakeagentcatalog.KeyManager(diskPlugin))

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)

	c := &Config{
		ServerAddr:      api.addr,
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     trustDomainURL,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          api.bundle,
		Metrics:         &telemetry.Blackhole{},
		Catalog:         cat,
		Clk:             clk,
	}

	m := newManager(c)
	require.NoError(t, m.Initialize(context.Background()))

	spiffeID := "spiffe://example.org/blog"
	audience := []string{"foo"}

	// nothing in cache, fetch fails
	svid, err := m.FetchJWTSVID(context.Background(), spiffeID, audience)
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
	svid, err = m.FetchJWTSVID(context.Background(), spiffeID, audience)
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
	svid, err = m.FetchJWTSVID(context.Background(), spiffeID, audience)
	require.NoError(t, err)
	require.Equal(t, tokenA, svid.Token)
	require.Equal(t, issuedAtA, svid.IssuedAt.Unix())
	require.Equal(t, expiresAtA, svid.ExpiresAt.Unix())

	// expire the cached JWT soon and make sure new JWT is fetched
	clk.Add(time.Second * 30)
	now = clk.Now()
	tokenC := "C"
	issuedAtC := now.Unix()
	expiresAtC := now.Add(time.Minute).Unix()
	fetchResp.Svid = &types.JWTSVID{
		Token:     tokenC,
		IssuedAt:  issuedAtC,
		ExpiresAt: expiresAtC,
	}
	svid, err = m.FetchJWTSVID(context.Background(), spiffeID, audience)
	require.NoError(t, err)
	require.Equal(t, tokenC, svid.Token)
	require.Equal(t, issuedAtC, svid.IssuedAt.Unix())
	require.Equal(t, expiresAtC, svid.ExpiresAt.Unix())

	// expire the JWT soon, fail the fetch, and make sure cached JWT is returned
	clk.Add(time.Second * 30)
	now = clk.Now()
	fetchResp.Svid = nil
	svid, err = m.FetchJWTSVID(context.Background(), spiffeID, audience)
	require.NoError(t, err)
	require.Equal(t, tokenC, svid.Token)
	require.Equal(t, issuedAtC, svid.IssuedAt.Unix())
	require.Equal(t, expiresAtC, svid.ExpiresAt.Unix())

	// now completely expire the JWT and make sure an error is returned, since
	// the fetch fails and the cached version is expired.
	clk.Add(time.Second * 30)
	svid, err = m.FetchJWTSVID(context.Background(), spiffeID, audience)
	require.Error(t, err)
	require.Nil(t, svid)
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

func regEntriesFromIdentities(ces []cache.Identity) (result []*common.RegistrationEntry) {
	for _, ce := range ces {
		result = append(result, ce.Entry)
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

	bundle *bundleutil.Bundle
	cakey  *ecdsa.PrivateKey

	svid    []*x509.Certificate
	svidKey *ecdsa.PrivateKey

	// Counts the number of requests received from clients
	getAuthorizedEntriesCount int32
	batchNewX509SVIDCount     int32

	clk clock.Clock

	agentv1.UnimplementedAgentServer
	bundlev1.UnimplementedBundleServer
	entryv1.UnimplementedEntryServer
	svidv1.UnimplementedSVIDServer
}

func newMockAPI(t *testing.T, config *mockAPIConfig) *mockAPI {
	ca, cakey := createCA(t, config.clk)

	h := &mockAPI{
		t:      t,
		c:      config,
		bundle: bundleutil.BundleFromRootCA(trustDomain.IDString(), ca),
		cakey:  cakey,
		clk:    config.clk,
	}
	serverID := idutil.ServerID(trustDomain)
	h.svid, h.svidKey = h.newSVID(serverID, 1*time.Hour)

	tlsConfig := &tls.Config{
		GetConfigForClient: h.getGRPCServerConfig,
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
			panic(fmt.Errorf("error starting mock server: %v", err))
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

func (h *mockAPI) GetAuthorizedEntries(ctx context.Context, req *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
	count := atomic.AddInt32(&h.getAuthorizedEntriesCount, 1)
	if h.c.getAuthorizedEntries != nil {
		return h.c.getAuthorizedEntries(h, count, req)
	}
	return nil, errors.New("no GetAuthorizedEntries implementation for test")
}

func (h *mockAPI) BatchNewX509SVID(ctx context.Context, req *svidv1.BatchNewX509SVIDRequest) (*svidv1.BatchNewX509SVIDResponse, error) {
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
				Status: api.CreateStatus(codes.NotFound, "entry %q not found", param.EntryId),
			})
			continue
		}
		svid := h.newSVIDFromCSR(spiffeid.RequireFromString(entry.SpiffeId), param.Csr)
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

func (h *mockAPI) NewJWTSVID(ctx context.Context, req *svidv1.NewJWTSVIDRequest) (*svidv1.NewJWTSVIDResponse, error) {
	if h.c.newJWTSVID != nil {
		return h.c.newJWTSVID(h, req)
	}
	return nil, errors.New("no FetchJWTSVID implementation for test")
}

func (h *mockAPI) GetBundle(ctx context.Context, req *bundlev1.GetBundleRequest) (*types.Bundle, error) {
	return api.BundleToProto(h.bundle.Proto())
}

func (h *mockAPI) GetFederatedBundle(ctx context.Context, req *bundlev1.GetFederatedBundleRequest) (*types.Bundle, error) {
	return &types.Bundle{
		TrustDomain: req.TrustDomain,
		X509Authorities: []*types.X509Certificate{
			{Asn1: h.ca().Raw},
		},
	}, nil
}

func (h *mockAPI) ca() *x509.Certificate {
	rootCAs := h.bundle.RootCAs()
	return rootCAs[len(rootCAs)-1]
}

func (h *mockAPI) newSVID(spiffeID spiffeid.ID, ttl time.Duration) ([]*x509.Certificate, *ecdsa.PrivateKey) {
	return createSVID(h.t, h.clk, h.ca(), h.cakey, spiffeID, ttl)
}

func (h *mockAPI) newSVIDFromCSR(spiffeID spiffeid.ID, csr []byte) []*x509.Certificate {
	return createSVIDFromCSR(h.t, h.clk, h.ca(), h.cakey, spiffeID, csr, h.c.svidTTL)
}

func (h *mockAPI) getGRPCServerConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	certChain := [][]byte{}
	for _, c := range h.svid {
		certChain = append(certChain, c.Raw)
	}
	certChain = append(certChain, h.ca().Raw)
	certs := []tls.Certificate{{
		Certificate: certChain,
		PrivateKey:  h.svidKey,
	}}

	roots := x509.NewCertPool()
	roots.AddCert(h.ca())

	return &tls.Config{
		ClientAuth:   tls.VerifyClientCertIfGiven,
		Certificates: certs,
		ClientCAs:    roots,
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

	ca, cakey, err := util.SelfSign(tmpl)
	if err != nil {
		t.Fatalf("cannot self sign ca template: %v", err)
	}
	return ca, cakey
}

func createSVID(t *testing.T, clk clock.Clock, ca *x509.Certificate, cakey *ecdsa.PrivateKey, spiffeID spiffeid.ID, ttl time.Duration) ([]*x509.Certificate, *ecdsa.PrivateKey) {
	tmpl, err := util.NewSVIDTemplate(clk, spiffeID.String())
	if err != nil {
		t.Fatalf("cannot create svid template for %s: %v", spiffeID, err)
	}

	tmpl.NotAfter = tmpl.NotBefore.Add(ttl)

	svid, svidkey, err := util.Sign(tmpl, ca, cakey)
	if err != nil {
		t.Fatalf("cannot sign svid template for %s: %v", spiffeID, err)
	}
	return []*x509.Certificate{svid}, svidkey
}

func createSVIDFromCSR(t *testing.T, clk clock.Clock, ca *x509.Certificate, cakey *ecdsa.PrivateKey, spiffeID spiffeid.ID, csr []byte, ttl int) []*x509.Certificate {
	req, err := x509.ParseCertificateRequest(csr)
	require.NoError(t, err)

	tmpl, err := util.NewSVIDTemplate(clk, spiffeID.String())
	require.NoError(t, err)
	tmpl.PublicKey = req.PublicKey
	tmpl.NotAfter = tmpl.NotBefore.Add(time.Duration(ttl) * time.Second)

	svid, _, err := util.Sign(tmpl, ca, cakey)
	require.NoError(t, err)

	return []*x509.Certificate{svid}
}

func initializeAndRunNewManager(t *testing.T, c *Config) (m *manager, closer func()) {
	m = newManager(c)
	return m, initializeAndRunManager(t, m)
}

func initializeAndRunManager(t *testing.T, m *manager) (closer func()) {
	ctx := context.Background()

	if err := m.Initialize(ctx); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
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
