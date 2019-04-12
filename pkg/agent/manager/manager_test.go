package manager

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path"
	"reflect"
	"sync"
	"testing"
	"time"

	testlog "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/disk"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/memory"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const (
	tmpSubdirName = "manager-test"
	trustDomain   = "example.org"
)

var (
	trustDomainID = url.URL{Scheme: "spiffe", Host: "example.org"}
)

var (
	testLogger, _ = testlog.NewNullLogger()
	regEntriesMap = util.GetRegistrationEntriesMap("manager_test_entries.json")
)

func TestInitializationFailure(t *testing.T) {
	clk := clock.New()
	ca, cakey := createCA(t, clk, trustDomain)
	baseSVID, baseSVIDKey := createSVID(t, clk, ca, cakey, "spiffe://"+trustDomain+"/agent", 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(memory.New()))

	c := &Config{
		SVID:        baseSVID,
		SVIDKey:     baseSVIDKey,
		Log:         testLogger,
		Metrics:     &telemetry.Blackhole{},
		TrustDomain: trustDomainID,
		Clk:         clk,
		Catalog:     cat,
	}
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}

	err = m.Initialize(context.Background())
	if err == nil {
		t.Fatal("wanted error")
	}
}

func TestStoreBundleOnStartup(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	clk := clock.New()
	ca, cakey := createCA(t, clk, trustDomain)
	baseSVID, baseSVIDKey := createSVID(t, clk, ca, cakey, "spiffe://"+trustDomain+"/agent", 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(disk.New()))

	c := &Config{
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		Metrics:         &telemetry.Blackhole{},
		TrustDomain:     trustDomainID,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          bundleutil.BundleFromRootCA("spiffe://"+trustDomain, ca),
		Clk:             clk,
		Catalog:         cat,
	}
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}

	util.RunWithTimeout(t, time.Second, func() {
		sub := m.SubscribeToBundleChanges()
		bundles := sub.Value()
		require.NotNil(t, bundles)
		bundle := bundles[trustDomainID.String()]
		require.Equal(t, bundle.RootCAs(), []*x509.Certificate{ca})
	})

	err = m.Initialize(context.Background())
	if err == nil {
		t.Fatal("manager was expected to fail during initialization")
	}

	// Althought start failed, the Bundle should have been saved, because it should be
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
	dir := createTempDir(t)
	defer removeTempDir(dir)

	clk := clock.New()
	ca, cakey := createCA(t, clk, trustDomain)
	baseSVID, baseSVIDKey := createSVID(t, clk, ca, cakey, "spiffe://"+trustDomain+"/agent", 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(disk.New()))

	c := &Config{
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		Metrics:         &telemetry.Blackhole{},
		TrustDomain:     trustDomainID,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Clk:             clk,
		Catalog:         cat,
	}

	_, err := ReadSVID(c.SVIDCachePath)
	if err != ErrNotCached {
		t.Fatalf("wanted: %v, got: %v", ErrNotCached, err)
	}

	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}

	err = m.Initialize(context.Background())
	if err == nil {
		t.Fatal("manager was expected to fail during initialization")
	}

	// Althought start failed, the SVID should have been saved, because it should be
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
	dir := createTempDir(t)
	defer removeTempDir(dir)

	clk := clock.New()
	ca, cakey := createCA(t, clk, trustDomain)
	baseSVID, baseSVIDKey := createSVID(t, clk, ca, cakey, "spiffe://"+trustDomain+"/agent", 1*time.Hour)

	cat := fakeagentcatalog.New()
	diskPlugin := disk.New()
	diskPlugin.Configure(context.Background(), &plugin.ConfigureRequest{Configuration: fmt.Sprintf("directory = \"%s\"", dir)})
	cat.SetKeyManager(fakeagentcatalog.KeyManager(diskPlugin))

	c := &Config{
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		Metrics:         &telemetry.Blackhole{},
		TrustDomain:     trustDomainID,
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

	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}

	err = m.Initialize(context.Background())
	if err == nil {
		t.Fatal("manager was expected to fail during initialization")
	}

	// Althought start failed, the SVID key should have been saved, because it should be
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
	dir := createTempDir(t)
	defer removeTempDir(dir)

	l, err := net.Listen("tcp", "localhost:")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	clk := clock.New()
	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:             t,
		trustDomain:   trustDomain,
		listener:      l,
		fetchX509SVID: fetchX509SVIDForTestHappyPathWithoutSyncNorRotation,
		svidTTL:       200,
	}, clk)
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(disk.New()))

	c := &Config{
		ServerAddr:      l.Addr().String(),
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     trustDomainID,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          apiHandler.bundle,
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

	me := m.MatchingEntries(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
	if len(me) != 2 {
		t.Fatal("expected 2 entries")
	}

	compareRegistrationEntries(t,
		regEntriesMap["resp2"],
		[]*common.RegistrationEntry{me[0].RegistrationEntry, me[1].RegistrationEntry})

	util.RunWithTimeout(t, 5*time.Second, func() {
		sub := m.SubscribeToCacheChanges(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
		u := <-sub.Updates()

		if len(u.Entries) != 2 {
			t.Fatal("expected 2 entries")
		}

		if len(u.Bundle.RootCAs()) != 1 {
			t.Fatal("expected 1 bundle root CA")
		}

		if !u.Bundle.EqualTo(apiHandler.bundle) {
			t.Fatal("received bundle should be equals to the server bundle")
		}

		compareRegistrationEntries(t,
			regEntriesMap["resp2"],
			[]*common.RegistrationEntry{u.Entries[0].RegistrationEntry, u.Entries[1].RegistrationEntry})
	})
}

func TestSVIDRotation(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	l, err := net.Listen("tcp", "localhost:")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	mockClk := clock.NewMock(t)

	baseTTL := 3
	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:             t,
		trustDomain:   trustDomain,
		listener:      l,
		fetchX509SVID: fetchX509SVID,
		svidTTL:       baseTTL,
	}, mockClk)
	apiHandler.start()
	defer apiHandler.stop()

	baseTTLSeconds := time.Duration(baseTTL) * time.Second
	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", baseTTLSeconds)

	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(memory.New()))

	c := &Config{
		Catalog:          cat,
		ServerAddr:       l.Addr().String(),
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomainID,
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           apiHandler.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: baseTTLSeconds / 2,
		SyncInterval:     1 * time.Hour,
		Clk:              mockClk,
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

	mockClk.WaitForTickerMulti(time.Second, 2, "svid rotater and syncer didn't create tickers after 1 second")
	// now that the ticker is created, cause a tick to happen
	mockClk.Add(baseTTLSeconds / 2)

	// Loop until we detect an SVID rotation
	util.RunWithTimeout(t, time.Second, func() {
		for {
			// If manager's current SVID is not equals to the first one we generated
			// it means it rotated, so we must exit the loop.
			s := m.svid.State()
			svid = s.SVID
			key = s.Key
			if !svidsEqual(svid, baseSVID) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	})

	if key == baseSVIDKey {
		t.Fatal("PrivateKey did not rotate")
	}
}

func TestSynchronization(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	l, err := net.Listen("tcp", "localhost:")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	mockClk := clock.NewMock(t)
	ttl := 3
	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:             t,
		trustDomain:   trustDomain,
		listener:      l,
		fetchX509SVID: fetchX509SVID,
		svidTTL:       ttl,
	}, mockClk)
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(disk.New()))

	c := &Config{
		ServerAddr:       l.Addr().String(),
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomainID,
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           apiHandler.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: time.Hour,
		SyncInterval:     time.Hour,
		Clk:              mockClk,
		Catalog:          cat,
	}

	m := newManager(t, c)

	sub := m.SubscribeToCacheChanges(cache.Selectors{
		{Type: "unix", Value: "uid:1111"},
		{Type: "spiffe_id", Value: "spiffe://example.org/spire/agent/join_token/abcd"},
	})
	defer sub.Finish()

	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Before synchronization
	entriesBefore := cacheEntriesAsMap(m.cache.Entries())
	if len(entriesBefore) != 3 {
		t.Fatalf("3 cached entries were expected; got %d", len(entriesBefore))
	}

	// This is the initial update based on the selector set
	u := <-sub.Updates()
	if len(u.Entries) != 3 {
		t.Fatalf("expected 3 entries, got: %d", len(u.Entries))
	}

	if len(u.Bundle.RootCAs()) != 1 {
		t.Fatal("expected 1 bundle root CA")
	}

	if !u.Bundle.EqualTo(apiHandler.bundle) {
		t.Fatal("received bundle should be equals to the server bundle")
	}

	for key, eu := range cacheEntriesAsMap(u.Entries) {
		eb, ok := entriesBefore[key]
		if !ok {
			t.Fatalf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
		}
		if eb != eu {
			t.Fatal("entry received does not match entry on cache")
		}
	}

	// SVIDs expire after 3 seconds, so we shouldn't expect any updates after
	// 1 second has elapsed.
	mockClk.Add(time.Second)
	require.NoError(t, m.synchronize(context.Background()))
	select {
	case <-sub.Updates():
		t.Fatal("update unexpected after 1 second")
	default:
	}

	// After advancing another second, the SVIDs should have been refreshed,
	// since the half-time has been exceeded.
	mockClk.Add(time.Second)
	require.NoError(t, m.synchronize(context.Background()))
	select {
	case u = <-sub.Updates():
	default:
		t.Fatal("update expected after 2 seconds")
	}

	// Make sure the update contains the updated entries and that the cache
	// has a consistent view.
	entriesAfter := cacheEntriesAsMap(m.cache.Entries())
	if len(entriesAfter) != 3 {
		t.Fatalf("expected 3 entries, got: %d", len(entriesAfter))
	}

	for key, eb := range entriesBefore {
		ea, ok := entriesAfter[key]
		if !ok {
			t.Fatalf("expected entry with EntryId=%v after synchronization", key)
		}
		if ea == eb {
			t.Fatalf("there is at least one entry that was not refreshed: %v", ea)
		}
	}

	if len(u.Entries) != 3 {
		t.Fatalf("expected 3 entries, got: %d", len(u.Entries))
	}

	if len(u.Bundle.RootCAs()) != 1 {
		t.Fatal("expected 1 bundle root CA")
	}

	if !u.Bundle.EqualTo(apiHandler.bundle) {
		t.Fatal("received bundle should be equals to the server bundle")
	}

	for key, eu := range cacheEntriesAsMap(u.Entries) {
		ea, ok := entriesAfter[key]
		if !ok {
			t.Fatalf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
		}
		if ea != eu {
			t.Fatal("entry received does not match entry on cache")
		}
	}
}

func TestSynchronizationClearsStaleCacheEntries(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	l, err := net.Listen("tcp", "localhost:")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	clk := clock.New()
	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:             t,
		trustDomain:   trustDomain,
		listener:      l,
		fetchX509SVID: fetchX509SVIDForStaleCacheTest,
		svidTTL:       3,
	}, clk)
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(disk.New()))

	c := &Config{
		ServerAddr:      l.Addr().String(),
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     trustDomainID,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          apiHandler.bundle,
		Metrics:         &telemetry.Blackhole{},
		Clk:             clk,
		Catalog:         cat,
	}

	m := newManager(t, c)

	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// after initialization, the cache should contain both resp1 and resp2
	// entries.
	compareRegistrationEntries(t,
		append(regEntriesMap["resp1"], regEntriesMap["resp2"]...),
		regEntriesFromCacheEntries(m.cache.Entries()))

	// manually synchronize again
	if err := m.synchronize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// now the cache should have entries from resp2 removed
	compareRegistrationEntries(t,
		regEntriesMap["resp1"],
		regEntriesFromCacheEntries(m.cache.Entries()))
}

func TestSynchronizationUpdatesRegistrationEntries(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	l, err := net.Listen("tcp", "localhost:")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	clk := clock.New()
	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:             t,
		trustDomain:   trustDomain,
		listener:      l,
		fetchX509SVID: fetchX509SVIDForRegistrationEntryUpdateTest,
		svidTTL:       3,
	}, clk)
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(disk.New()))

	c := &Config{
		ServerAddr:      l.Addr().String(),
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     trustDomainID,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          apiHandler.bundle,
		Metrics:         &telemetry.Blackhole{},
		Clk:             clk,
		Catalog:         cat,
	}

	m := newManager(t, c)

	if err := m.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// after initialization, the cache should contain resp2 entries
	compareRegistrationEntries(t,
		regEntriesMap["resp2"],
		regEntriesFromCacheEntries(m.cache.Entries()))

	// manually synchronize again
	if err := m.synchronize(context.Background()); err != nil {
		t.Fatal(err)
	}

	// now the cache should have the updated entries from resp3
	compareRegistrationEntries(t,
		regEntriesMap["resp3"],
		regEntriesFromCacheEntries(m.cache.Entries()))
}

func TestSubscribersGetUpToDateBundle(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	l, err := net.Listen("tcp", "localhost:")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	clk := clock.New()
	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:             t,
		trustDomain:   trustDomain,
		listener:      l,
		fetchX509SVID: fetchX509SVIDForTestSubscribersGetUpToDateBundle,
		svidTTL:       200,
	}, clk)
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(disk.New()))

	c := &Config{
		ServerAddr:       l.Addr().String(),
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomainID,
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           apiHandler.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: 1 * time.Hour,
		SyncInterval:     1 * time.Hour,
		Clk:              clk,
		Catalog:          cat,
	}

	m := newManager(t, c)

	sub := m.SubscribeToCacheChanges(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})

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
	dir := createTempDir(t)
	defer removeTempDir(dir)

	l, err := net.Listen("tcp", "localhost:")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	mockClk := clock.NewMock(t)
	ttl := 3
	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:             t,
		trustDomain:   trustDomain,
		listener:      l,
		fetchX509SVID: fetchX509SVIDForTestSurvivesCARotation,
		// Give a low ttl to get expired entries on each synchronization, forcing
		// the manager to fetch entries from the server.
		svidTTL: ttl,
	}, mockClk)
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)
	cat := fakeagentcatalog.New()
	cat.SetKeyManager(fakeagentcatalog.KeyManager(disk.New()))

	ttlSeconds := time.Duration(ttl) * time.Second
	syncInterval := ttlSeconds / 2
	c := &Config{
		ServerAddr:       l.Addr().String(),
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomainID,
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           apiHandler.bundle,
		Metrics:          &telemetry.Blackhole{},
		RotationInterval: 1 * time.Hour,
		SyncInterval:     syncInterval,
		Clk:              mockClk,
		Catalog:          cat,
	}

	m := newManager(t, c)

	sub := m.SubscribeToCacheChanges(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
	// This should be the update received when Subscribe function was called.
	updates := sub.Updates()
	initialUpdate := <-updates
	initialRoot := initialUpdate.Bundle.RootCAs()[0]

	defer initializeAndRunManager(t, m)()

	// Second FetchX509 request will create a new CA
	mockClk.Add(syncInterval)
	newCAUpdate := <-updates
	newRoots := newCAUpdate.Bundle.RootCAs()
	require.Contains(t, newRoots, initialRoot)
	require.Len(t, newRoots, 2)
}

func TestFetchJWTSVID(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	l, err := net.Listen("tcp", "localhost:")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	fetchResp := &node.FetchJWTSVIDResponse{}

	mockClk := clock.NewMock(t)
	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:           t,
		trustDomain: trustDomain,
		listener:    l,
		fetchJWTSVID: func(h *mockNodeAPIHandler, req *node.FetchJWTSVIDRequest) (*node.FetchJWTSVIDResponse, error) {
			return fetchResp, nil
		},
		svidTTL: 200,
	}, mockClk)

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)

	apiHandler.start()
	defer apiHandler.stop()

	c := &Config{
		ServerAddr:      l.Addr().String(),
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     trustDomainID,
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          apiHandler.bundle,
		Metrics:         &telemetry.Blackhole{},
		Clk:             mockClk,
	}

	m := newManager(t, c)

	spiffeID := "spiffe://example.org"
	audience := []string{"foo"}

	// nothing in cache, fetch fails
	svid, err := m.FetchJWTSVID(context.Background(), spiffeID, audience)
	require.Error(t, err)
	require.Empty(t, svid)

	now := mockClk.Now()
	// fetch succeeds
	tokenA := "A"
	issuedAtA := now.Unix()
	expiresAtA := now.Add(time.Minute).Unix()
	fetchResp.Svid = &node.JWTSVID{
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
	fetchResp.Svid = &node.JWTSVID{
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
	mockClk.Add(time.Second * 30)
	now = mockClk.Now()
	tokenC := "C"
	issuedAtC := now.Unix()
	expiresAtC := now.Add(time.Minute).Unix()
	fetchResp.Svid = &node.JWTSVID{
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
	mockClk.Add(time.Second * 30)
	now = mockClk.Now()
	fetchResp.Svid = nil
	svid, err = m.FetchJWTSVID(context.Background(), spiffeID, audience)
	require.NoError(t, err)
	require.Equal(t, tokenC, svid.Token)
	require.Equal(t, issuedAtC, svid.IssuedAt.Unix())
	require.Equal(t, expiresAtC, svid.ExpiresAt.Unix())

	// now completely expire the JWT and make sure an error is returned, since
	// the fetch fails and the cached version is expired.
	mockClk.Add(time.Second * 30)
	svid, err = m.FetchJWTSVID(context.Background(), spiffeID, audience)
	require.Error(t, err)
	require.Nil(t, svid)
}

func fetchX509SVIDForTestHappyPathWithoutSyncNorRotation(h *mockNodeAPIHandler, req *node.FetchX509SVIDRequest, stream node.Node_FetchX509SVIDServer) error {
	switch h.getCountRequest() {
	case 1:
		if len(req.Csrs) != 0 {
			return fmt.Errorf("server expected 0 CRS, got: %d. reqCount: %d", len(req.Csrs), h.getCountRequest())
		}

		return stream.Send(newFetchX509SVIDResponse([]string{"resp1", "resp2"}, nil, h.bundle))
	case 2:
		if len(req.Csrs) != 3 {
			return fmt.Errorf("server expected 3 CRS, got: %d. reqCount: %d", len(req.Csrs), h.getCountRequest())
		}

		svids, err := h.makeSvids(req.Csrs)
		if err != nil {
			return err
		}

		return stream.Send(newFetchX509SVIDResponse(
			[]string{"resp1", "resp2"},
			svids,
			h.bundle))
	default:
		return fmt.Errorf("server received unexpected call. reqCount: %d", h.getCountRequest())
	}
}

func fetchX509SVID(h *mockNodeAPIHandler, req *node.FetchX509SVIDRequest, stream node.Node_FetchX509SVIDServer) error {
	svid, err := h.getCertFromCtx(stream.Context())
	if err != nil {
		return fmt.Errorf("cannot get SVID from stream context: %v. reqCount: %d", err, h.getCountRequest())
	}

	spiffeID, err := getSpiffeIDFromSVID(svid)
	if err != nil {
		return fmt.Errorf("cannot get spiffeID from SVID: %v. reqCount: %d", err, h.getCountRequest())
	}

	var resps []string
	switch spiffeID {
	case "spiffe://example.org/spire/agent/join_token/abcd":
		resps = append(resps, "resp1", "resp2")
	case "spiffe://example.org/spire/agent":
		resps = append(resps, "resp2")
	default:
		resps = append(resps, "resp0")
	}

	svids, err := h.makeSvids(req.Csrs)
	if err != nil {
		return err
	}

	return stream.Send(newFetchX509SVIDResponse(resps, svids, h.bundle))
}

func fetchX509SVIDForStaleCacheTest(h *mockNodeAPIHandler, req *node.FetchX509SVIDRequest, stream node.Node_FetchX509SVIDServer) error {
	svids, err := h.makeSvids(req.Csrs)
	if err != nil {
		return err
	}

	switch h.getCountRequest() {
	case 1:
		return stream.Send(newFetchX509SVIDResponse([]string{"resp1", "resp2"}, nil, h.bundle))
	case 2:
		return stream.Send(newFetchX509SVIDResponse([]string{"resp1", "resp2"}, svids, h.bundle))
	case 3:
		return stream.Send(newFetchX509SVIDResponse([]string{"resp1"}, nil, h.bundle))
	case 4:
		return stream.Send(newFetchX509SVIDResponse([]string{"resp1"}, svids, h.bundle))
	}
	return stream.Send(newFetchX509SVIDResponse(nil, nil, h.bundle))
}

func fetchX509SVIDForRegistrationEntryUpdateTest(h *mockNodeAPIHandler, req *node.FetchX509SVIDRequest, stream node.Node_FetchX509SVIDServer) error {
	svids, err := h.makeSvids(req.Csrs)
	if err != nil {
		return err
	}

	switch h.getCountRequest() {
	case 1:
		return stream.Send(newFetchX509SVIDResponse([]string{"resp2"}, nil, h.bundle))
	case 2:
		return stream.Send(newFetchX509SVIDResponse([]string{"resp2"}, svids, h.bundle))
	case 3:
		return stream.Send(newFetchX509SVIDResponse([]string{"resp3"}, nil, h.bundle))
	}
	return stream.Send(newFetchX509SVIDResponse(nil, nil, h.bundle))
}

func fetchX509SVIDForTestSubscribersGetUpToDateBundle(h *mockNodeAPIHandler, req *node.FetchX509SVIDRequest, stream node.Node_FetchX509SVIDServer) error {
	switch h.getCountRequest() {
	case 2:
		ca, _ := createCA(h.c.t, h.clk, h.c.trustDomain)
		h.bundle.AppendRootCA(ca)
	}

	return fetchX509SVID(h, req, stream)
}

func fetchX509SVIDForTestSurvivesCARotation(h *mockNodeAPIHandler, req *node.FetchX509SVIDRequest, stream node.Node_FetchX509SVIDServer) error {
	switch h.getCountRequest() {
	case 2:
		ca, key := createCA(h.c.t, h.clk, h.c.trustDomain)
		h.cakey = key
		h.bundle.AppendRootCA(ca)
	case 5:
		return fmt.Errorf("i'm an error")
	}

	return fetchX509SVID(h, req, stream)
}

func newFetchX509SVIDResponse(regEntriesKeys []string, svids svidMap, bundle *bundleutil.Bundle) *node.FetchX509SVIDResponse {
	bundleBytes := &bytes.Buffer{}
	for _, c := range bundle.RootCAs() {
		bundleBytes.Write(c.Raw)
	}

	var regEntries []*common.RegistrationEntry
	for _, regEntriesKey := range regEntriesKeys {
		for _, regEntry := range regEntriesMap[regEntriesKey] {
			regEntries = append(regEntries, regEntry)
		}
	}

	return &node.FetchX509SVIDResponse{
		SvidUpdate: &node.X509SVIDUpdate{
			RegistrationEntries: regEntries,
			Svids:               svids,
			Bundles: map[string]*common.Bundle{
				bundle.TrustDomainID(): bundle.Proto(),
			},
		},
	}
}

func regEntriesAsMap(res []*common.RegistrationEntry) (result map[string]*common.RegistrationEntry) {
	result = map[string]*common.RegistrationEntry{}
	for _, re := range res {
		result[re.EntryId] = re
	}
	return result
}

func cacheEntriesAsMap(ces []*cache.Entry) (result map[string]*cache.Entry) {
	result = map[string]*cache.Entry{}
	for _, ce := range ces {
		result[ce.RegistrationEntry.EntryId] = ce
	}
	return result
}

func regEntriesFromCacheEntries(ces []*cache.Entry) (result []*common.RegistrationEntry) {
	for _, ce := range ces {
		result = append(result, ce.RegistrationEntry)
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

type svidMap map[string]*node.X509SVID

type mockNodeAPIHandlerConfig struct {
	t           *testing.T
	trustDomain string

	listener net.Listener

	// Callbacks used to build the response according to the request and state of mockNodeAPIHandler.
	fetchX509SVID func(*mockNodeAPIHandler, *node.FetchX509SVIDRequest, node.Node_FetchX509SVIDServer) error
	fetchJWTSVID  func(*mockNodeAPIHandler, *node.FetchJWTSVIDRequest) (*node.FetchJWTSVIDResponse, error)

	svidTTL int
}

type mockNodeAPIHandler struct {
	c *mockNodeAPIHandlerConfig

	bundle *bundleutil.Bundle
	cakey  *ecdsa.PrivateKey

	svid    []*x509.Certificate
	svidKey *ecdsa.PrivateKey

	serverID string

	server *grpc.Server
	creds  grpc.ServerOption

	// Counts the number of requests received from clients
	reqCount int

	clk clock.Clock
	// Lock for the count
	mtx sync.RWMutex
}

func newMockNodeAPIHandler(config *mockNodeAPIHandlerConfig, clk clock.Clock) *mockNodeAPIHandler {
	ca, cakey := createCA(config.t, clk, config.trustDomain)

	h := &mockNodeAPIHandler{
		c:        config,
		bundle:   bundleutil.BundleFromRootCA("spiffe://"+config.trustDomain, ca),
		cakey:    cakey,
		serverID: idutil.ServerID(config.trustDomain),
		clk:      clk,
	}

	h.svid, h.svidKey = h.newSVID(h.serverID, 1*time.Hour)

	tlsConfig := &tls.Config{
		GetConfigForClient: h.getGRPCServerConfig,
	}

	h.creds = grpc.Creds(credentials.NewTLS(tlsConfig))
	return h
}

func (h *mockNodeAPIHandler) makeSvids(csrs [][]byte) (svidMap, error) {
	svids := make(svidMap)
	for _, csr := range csrs {
		svid := h.newSVIDFromCSR(csr)
		spiffeID, err := getSpiffeIDFromSVID(svid[0])
		if err != nil {
			return nil, fmt.Errorf("cannot get spiffeID from SVID: %v. reqCount: %d", err, h.getCountRequest())
		}
		svids[spiffeID] = &node.X509SVID{
			CertChain: x509util.DERFromCertificates(svid),
			ExpiresAt: svid[0].NotAfter.Unix(),
		}
	}
	return svids, nil
}

func (h *mockNodeAPIHandler) getCountRequest() int {
	h.mtx.RLock()
	defer h.mtx.RUnlock()
	return h.reqCount
}

func (h *mockNodeAPIHandler) countRequest() {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	h.reqCount++
}

func (h *mockNodeAPIHandler) Attest(stream node.Node_AttestServer) error {
	h.c.t.Fatalf("unexpected call to Attest")
	return nil
}

func (h *mockNodeAPIHandler) FetchX509SVID(stream node.Node_FetchX509SVIDServer) error {
	h.countRequest()

	req, err := stream.Recv()
	if err != nil {
		return err
	}
	if h.c.fetchX509SVID != nil {
		return h.c.fetchX509SVID(h, req, stream)
	}
	return nil
}

func (h *mockNodeAPIHandler) FetchJWTSVID(ctx context.Context, req *node.FetchJWTSVIDRequest) (*node.FetchJWTSVIDResponse, error) {
	h.countRequest()
	if h.c.fetchJWTSVID != nil {
		return h.c.fetchJWTSVID(h, req)
	}
	return nil, errors.New("oh noes")
}

func (h *mockNodeAPIHandler) start() {
	s := grpc.NewServer(h.creds)
	node.RegisterNodeServer(s, h)
	h.server = s

	go func() {
		err := h.server.Serve(h.c.listener)
		if err != nil {
			panic(fmt.Errorf("error starting mock server: %v", err))
		}
	}()

	// Let grpc server initialize
	time.Sleep(1 * time.Millisecond)
}

func (h *mockNodeAPIHandler) stop() {
	h.server.Stop()
}

func (h *mockNodeAPIHandler) ca() *x509.Certificate {
	rootCAs := h.bundle.RootCAs()
	return rootCAs[len(rootCAs)-1]
}

func (h *mockNodeAPIHandler) newSVID(spiffeID string, ttl time.Duration) ([]*x509.Certificate, *ecdsa.PrivateKey) {
	return createSVID(h.c.t, h.clk, h.ca(), h.cakey, spiffeID, ttl)
}

func (h *mockNodeAPIHandler) newSVIDFromCSR(csr []byte) []*x509.Certificate {
	return createSVIDFromCSR(h.c.t, h.clk, h.ca(), h.cakey, csr, h.c.svidTTL)
}

func (h *mockNodeAPIHandler) getGRPCServerConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
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

	c := &tls.Config{
		ClientAuth:   tls.VerifyClientCertIfGiven,
		Certificates: certs,
		ClientCAs:    roots,
	}

	return c, nil
}

func (h *mockNodeAPIHandler) getCertFromCtx(ctx context.Context) (certificate *x509.Certificate, err error) {
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

func createTempDir(t *testing.T) string {
	dir, err := ioutil.TempDir("", tmpSubdirName)
	if err != nil {
		t.Fatalf("could not create temp dir: %v", err)
	}
	return dir
}

func removeTempDir(dir string) {
	os.RemoveAll(dir)
}

func createCA(t *testing.T, clk clock.Clock, trustDomain string) (*x509.Certificate, *ecdsa.PrivateKey) {
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

func createSVID(t *testing.T, clk clock.Clock, ca *x509.Certificate, cakey *ecdsa.PrivateKey, spiffeID string, ttl time.Duration) ([]*x509.Certificate, *ecdsa.PrivateKey) {
	tmpl, err := util.NewSVIDTemplate(clk, spiffeID)
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

func createSVIDFromCSR(t *testing.T, clk clock.Clock, ca *x509.Certificate, cakey *ecdsa.PrivateKey, csr []byte, ttl int) []*x509.Certificate {
	tmpl, err := util.NewSVIDTemplateFromCSR(clk, csr, ca, ttl)
	if err != nil {
		t.Fatalf("cannot create svid template from CSR: %v", err)
	}

	svid, _, err := util.Sign(tmpl, ca, cakey)
	if err != nil {
		t.Fatalf("cannot sign svid template for CSR: %v", err)
	}
	return []*x509.Certificate{svid}
}

func newManager(t *testing.T, c *Config) *manager {
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func initializeAndRunNewManager(t *testing.T, c *Config) (m *manager, closer func()) {
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
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
