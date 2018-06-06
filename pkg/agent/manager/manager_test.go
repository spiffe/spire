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
	"sync"
	"testing"
	"time"

	testlog "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/util"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const (
	tmpSubdirName = "manager-test"
)

var (
	testLogger, _ = testlog.NewNullLogger()
	regEntriesMap = util.GetRegistrationEntriesMap("manager_test_entries.json")
)

func TestInitializationFailure(t *testing.T) {
	trustDomain := "somedomain.com"
	ca, cakey := createCA(t, trustDomain)
	baseSVID, baseSVIDKey := createSVID(t, ca, cakey, "spiffe://"+trustDomain+"/agent", 1*time.Hour)

	c := &Config{
		ServerAddr:  &net.TCPAddr{},
		SVID:        baseSVID,
		SVIDKey:     baseSVIDKey,
		Log:         testLogger,
		TrustDomain: url.URL{Host: trustDomain},
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

	trustDomain := "somedomain.com"
	ca, cakey := createCA(t, trustDomain)
	baseSVID, baseSVIDKey := createSVID(t, ca, cakey, "spiffe://"+trustDomain+"/agent", 1*time.Hour)

	c := &Config{
		ServerAddr:      &net.TCPAddr{},
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     url.URL{Host: trustDomain},
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          []*x509.Certificate{ca},
	}
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}

	if !m.bundleAlreadyCached([]*x509.Certificate{ca}) {
		t.Fatal("bundle should have been cached in memory")
	}

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

	trustDomain := "somedomain.com"
	ca, cakey := createCA(t, trustDomain)
	baseSVID, baseSVIDKey := createSVID(t, ca, cakey, "spiffe://"+trustDomain+"/agent", 1*time.Hour)

	c := &Config{
		ServerAddr:      &net.TCPAddr{},
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     url.URL{Host: trustDomain},
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
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
	cert, err := ReadSVID(c.SVIDCachePath)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Equal(baseSVID) {
		t.Fatal("SVID was not correctly stored.")
	}
}

func TestHappyPathWithoutSyncNorRotation(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	trustDomain := "example.org"

	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:                 t,
		trustDomain:       trustDomain,
		dir:               dir,
		fetchSVIDResponse: fetchSVIDResponseForTestHappyPathWithoutSyncNorRotation,
		svidTTL:           200,
	})
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)

	c := &Config{
		ServerAddr: &net.UnixAddr{
			Net:  "unix",
			Name: apiHandler.sockPath,
		},
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     url.URL{Host: trustDomain},
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          apiHandler.bundle,
		Tel:             &telemetry.Blackhole{},
	}

	m, closer := initializeAndRunNewManager(t, c)
	defer closer()

	cert := m.svid.State().SVID
	if !cert.Equal(baseSVID) {
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

		if len(u.Bundle) != 1 {
			t.Fatal("expected 1 bundle")
		}

		if !u.Bundle[0].Equal(apiHandler.bundle[0]) {
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

	trustDomain := "example.org"

	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:                 t,
		trustDomain:       trustDomain,
		dir:               dir,
		fetchSVIDResponse: fetchSVIDResponse,
		svidTTL:           3,
	})
	apiHandler.start()
	defer apiHandler.stop()

	baseTTL := 3 * time.Second
	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", baseTTL)

	c := &Config{
		ServerAddr: &net.UnixAddr{
			Net:  "unix",
			Name: apiHandler.sockPath,
		},
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      url.URL{Host: trustDomain},
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           apiHandler.bundle,
		Tel:              &telemetry.Blackhole{},
		RotationInterval: baseTTL / 2,
		SyncInterval:     1 * time.Hour,
	}

	m, closer := initializeAndRunNewManager(t, c)
	defer closer()

	cert := m.svid.State().SVID
	if !cert.Equal(baseSVID) {
		t.Fatal("SVID is not equals to configured one")
	}

	key := m.svid.State().Key
	if key != baseSVIDKey {
		t.Fatal("PrivateKey is not equals to configured one")
	}

	// Loop until we detect an SVID rotation
	util.RunWithTimeout(t, 2*m.c.RotationInterval, func() {
		for {
			// If manager's current SVID is not equals to the first one we generated
			// it means it rotated, so we must exit the loop.
			s := m.svid.State()
			cert = s.SVID
			key = s.Key
			if !cert.Equal(baseSVID) {
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

	trustDomain := "example.org"

	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:                 t,
		trustDomain:       trustDomain,
		dir:               dir,
		fetchSVIDResponse: fetchSVIDResponse,
		svidTTL:           3,
	})
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)

	c := &Config{
		ServerAddr: &net.UnixAddr{
			Net:  "unix",
			Name: apiHandler.sockPath,
		},
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      url.URL{Host: trustDomain},
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           apiHandler.bundle,
		Tel:              &telemetry.Blackhole{},
		RotationInterval: 1 * time.Hour,
		SyncInterval:     3 * time.Second,
	}

	m, closer := initializeAndRunNewManager(t, c)
	defer closer()

	sub := m.SubscribeToCacheChanges(cache.Selectors{
		&common.Selector{Type: "unix", Value: "uid:1111"},
		&common.Selector{Type: "spiffe_id", Value: "spiffe://example.org/spire/agent/join_token/abcd"},
	})

	// Before synchronization
	entriesBefore := cacheEntriesAsMap(m.cache.Entries())
	if len(entriesBefore) != 3 {
		t.Fatalf("3 cached entries were expected; got %d", len(entriesBefore))
	}

	util.RunWithTimeout(t, 5*time.Second, func() {
		u := <-sub.Updates()

		if len(u.Entries) != 3 {
			t.Fatalf("expected 3 entries, got: %d", len(u.Entries))
		}

		if len(u.Bundle) != 1 {
			t.Fatal("expected 1 bundle")
		}

		if !u.Bundle[0].Equal(apiHandler.bundle[0]) {
			t.Fatal("received bundle should be equals to the server bundle")
		}

		entriesUpdated := cacheEntriesAsMap(u.Entries)
		for key, eu := range entriesUpdated {
			eb, ok := entriesBefore[key]
			if !ok {
				t.Fatalf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
			}
			if eb != eu {
				t.Fatal("entry received does not match entry on cache")
			}
		}
	})

	util.RunWithTimeout(t, 2*m.c.SyncInterval, func() {
		// There should be 3 updates after sync, because we are subcribed to selectors that
		// matches with 3 entries that were renewed on the cache.
		updates := sub.Updates()
		<-updates
		<-updates
		u := <-updates

		entriesAfter := cacheEntriesAsMap(m.cache.Entries())
		if len(entriesAfter) != 3 {
			t.Fatal("3 cached entries were expected")
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

		if len(u.Bundle) != 1 {
			t.Fatal("expected 1 bundle")
		}

		if !u.Bundle[0].Equal(apiHandler.bundle[0]) {
			t.Fatal("received bundle should be equals to the server bundle")
		}

		entriesUpdated := cacheEntriesAsMap(u.Entries)
		for key, eu := range entriesUpdated {
			ea, ok := entriesAfter[key]
			if !ok {
				t.Fatalf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
			}
			if ea != eu {
				t.Fatal("entry received does not match entry on cache")
			}
		}
	})
}

func TestSynchronizationClearsStaleCacheEntries(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	trustDomain := "example.org"

	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:                 t,
		trustDomain:       trustDomain,
		dir:               dir,
		fetchSVIDResponse: fetchSVIDResponseForStaleCacheTest,
		svidTTL:           3,
	})
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)

	c := &Config{
		ServerAddr: &net.UnixAddr{
			Net:  "unix",
			Name: apiHandler.sockPath,
		},
		SVID:            baseSVID,
		SVIDKey:         baseSVIDKey,
		Log:             testLogger,
		TrustDomain:     url.URL{Host: trustDomain},
		SVIDCachePath:   path.Join(dir, "svid.der"),
		BundleCachePath: path.Join(dir, "bundle.der"),
		Bundle:          apiHandler.bundle,
		Tel:             &telemetry.Blackhole{},
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
	if err := m.synchronize(); err != nil {
		t.Fatal(err)
	}

	// now the cache should have entries from resp2 removed
	compareRegistrationEntries(t,
		regEntriesMap["resp1"],
		regEntriesFromCacheEntries(m.cache.Entries()))
}

func TestSubscribersGetUpToDateBundle(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	trustDomain := "example.org"

	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:                 t,
		trustDomain:       trustDomain,
		dir:               dir,
		fetchSVIDResponse: fetchSVIDResponseForTestSubscribersGetUpToDateBundle,
		svidTTL:           200,
	})
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)

	c := &Config{
		ServerAddr: &net.UnixAddr{
			Net:  "unix",
			Name: apiHandler.sockPath,
		},
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      url.URL{Host: trustDomain},
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           []*x509.Certificate{apiHandler.bundle[0]},
		Tel:              &telemetry.Blackhole{},
		RotationInterval: 1 * time.Hour,
		SyncInterval:     1 * time.Hour,
	}

	m := newManager(t, c)

	sub := m.SubscribeToCacheChanges(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})

	defer initializeAndRunManager(t, m)()

	util.RunWithTimeout(t, 1*time.Second, func() {
		// Update should contain a new bundle.
		u := <-sub.Updates()
		if len(u.Bundle) != 2 {
			t.Fatalf("expected 2 bundles, got: %d", len(u.Bundle))
		}
		if !u.Bundle[0].Equal(c.Bundle[0]) {
			t.Fatal("old bundles were expected to be equals")
		}
		if !u.Bundle[1].Equal(apiHandler.bundle[1]) {
			t.Fatal("new bundles were expected to be equals")
		}
	})
}

func TestSurvivesCARotation(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	trustDomain := "example.org"

	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:                 t,
		trustDomain:       trustDomain,
		dir:               dir,
		fetchSVIDResponse: fetchSVIDResponseForTestSurvivesCARotation,
		// Give a low ttl to get expired entries on each synchronization, forcing
		// the manager to fetch entries from the server.
		svidTTL: 3,
	})
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)

	c := &Config{
		ServerAddr: &net.UnixAddr{
			Net:  "unix",
			Name: apiHandler.sockPath,
		},
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      url.URL{Host: trustDomain},
		SVIDCachePath:    path.Join(dir, "svid.der"),
		BundleCachePath:  path.Join(dir, "bundle.der"),
		Bundle:           []*x509.Certificate{apiHandler.bundle[0]},
		Tel:              &telemetry.Blackhole{},
		RotationInterval: 1 * time.Hour,
		// We want frequent synchronizations to speed up the test.
		SyncInterval: 1 * time.Second,
	}

	m := newManager(t, c)

	sub := m.SubscribeToCacheChanges(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
	// This should be the update received when Subscribe function was called.
	updates := sub.Updates()
	<-updates

	defer initializeAndRunManager(t, m)()

	// Get latest update
	util.RunWithTimeout(t, 4*time.Second, func() {
		<-updates
	})

	// Wait update, it should be received once connection is restablished by synchronization
	elapsed := util.RunWithTimeout(t, 8*time.Second, func() {
		<-updates
	})

	// If we received an update too soon, then we assume that the connection to the server never
	// was lost and hence we are not testing if the manager can survive the CA rotation.
	if elapsed < time.Second {
		t.Fatalf("update received too soon: elapsed %dms since last one", elapsed/time.Millisecond)
	}
}

func fetchSVIDResponseForTestHappyPathWithoutSyncNorRotation(h *mockNodeAPIHandler, req *node.FetchSVIDRequest, stream node.Node_FetchSVIDServer) error {
	switch h.reqCount {
	case 1:
		if len(req.Csrs) != 0 {
			return fmt.Errorf("server expected 0 CRS, got: %d. reqCount: %d", len(req.Csrs), h.reqCount)
		}

		return stream.Send(newFetchSVIDResponse([]string{"resp1", "resp2"}, nil, h.bundle))
	case 2:
		if len(req.Csrs) != 3 {
			return fmt.Errorf("server expected 3 CRS, got: %d. reqCount: %d", len(req.Csrs), h.reqCount)
		}

		svids, err := h.makeSvids(req.Csrs)
		if err != nil {
			return err
		}

		return stream.Send(newFetchSVIDResponse(
			[]string{"resp1", "resp2"},
			svids,
			h.bundle))
	default:
		return fmt.Errorf("server received unexpected call. reqCount: %d", h.reqCount)
	}
}

func fetchSVIDResponse(h *mockNodeAPIHandler, req *node.FetchSVIDRequest, stream node.Node_FetchSVIDServer) error {
	svid, err := h.getCertFromCtx(stream.Context())
	if err != nil {
		return fmt.Errorf("cannot get SVID from stream context: %v. reqCount: %d", err, h.reqCount)
	}

	spiffeID, err := getSpiffeIDFromSVID(svid)
	if err != nil {
		return fmt.Errorf("cannot get spiffeID from SVID: %v. reqCount: %d", err, h.reqCount)
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

	return stream.Send(newFetchSVIDResponse(resps, svids, h.bundle))
}

func fetchSVIDResponseForStaleCacheTest(h *mockNodeAPIHandler, req *node.FetchSVIDRequest, stream node.Node_FetchSVIDServer) error {
	svids, err := h.makeSvids(req.Csrs)
	if err != nil {
		return err
	}

	switch h.reqCount {
	case 1:
		return stream.Send(newFetchSVIDResponse([]string{"resp1", "resp2"}, nil, h.bundle))
	case 2:
		return stream.Send(newFetchSVIDResponse([]string{"resp1", "resp2"}, svids, h.bundle))
	case 3:
		return stream.Send(newFetchSVIDResponse([]string{"resp1"}, nil, h.bundle))
	case 4:
		return stream.Send(newFetchSVIDResponse([]string{"resp1"}, svids, h.bundle))
	}
	return stream.Send(newFetchSVIDResponse(nil, nil, h.bundle))
}

func fetchSVIDResponseForTestSubscribersGetUpToDateBundle(h *mockNodeAPIHandler, req *node.FetchSVIDRequest, stream node.Node_FetchSVIDServer) error {
	switch h.reqCount {
	case 2:
		ca, _ := createCA(h.c.t, h.c.trustDomain)
		h.bundle = append(h.bundle, ca)
	}

	return fetchSVIDResponse(h, req, stream)
}

func fetchSVIDResponseForTestSurvivesCARotation(h *mockNodeAPIHandler, req *node.FetchSVIDRequest, stream node.Node_FetchSVIDServer) error {
	switch h.reqCount {
	case 2:
		ca, key := createCA(h.c.t, h.c.trustDomain)
		h.cakey = key
		h.bundle = append(h.bundle, ca)
	case 5:
		h.stop()
		time.Sleep(3 * time.Second)
		h.start()
		return fmt.Errorf("server was restarted")
	}

	return fetchSVIDResponse(h, req, stream)
}

func newFetchSVIDResponse(regEntriesKeys []string, svids svidMap, bundle []*x509.Certificate) *node.FetchSVIDResponse {
	bundleBytes := &bytes.Buffer{}
	for _, c := range bundle {
		bundleBytes.Write(c.Raw)
	}

	var regEntries []*common.RegistrationEntry
	for _, regEntriesKey := range regEntriesKeys {
		for _, regEntry := range regEntriesMap[regEntriesKey] {
			regEntries = append(regEntries, regEntry)
		}
	}

	return &node.FetchSVIDResponse{
		SvidUpdate: &node.SvidUpdate{
			RegistrationEntries: regEntries,
			Svids:               svids,
			Bundle:              bundleBytes.Bytes(),
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

type svidMap map[string]*node.Svid

type mockNodeAPIHandlerConfig struct {
	t           *testing.T
	trustDomain string
	// Directory used to save server related files, like unix sockets files.
	dir string
	// Callback used to build the response according to the request and state of mockNodeAPIHandler.
	fetchSVIDResponse func(*mockNodeAPIHandler, *node.FetchSVIDRequest, node.Node_FetchSVIDServer) error

	svidTTL int
}

type mockNodeAPIHandler struct {
	c *mockNodeAPIHandlerConfig

	bundle []*x509.Certificate
	cakey  *ecdsa.PrivateKey

	svid    *x509.Certificate
	svidKey *ecdsa.PrivateKey

	serverID string

	sockPath string
	server   *grpc.Server
	creds    grpc.ServerOption

	// Counts the number of requests received from clients
	reqCount int

	delay time.Duration
}

func newMockNodeAPIHandler(config *mockNodeAPIHandlerConfig) *mockNodeAPIHandler {
	ca, cakey := createCA(config.t, config.trustDomain)

	h := &mockNodeAPIHandler{
		c:        config,
		bundle:   []*x509.Certificate{ca},
		cakey:    cakey,
		sockPath: path.Join(config.dir, "node_api.sock"),
		serverID: "spiffe://" + config.trustDomain + "/spire/server",
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
		spiffeID, err := getSpiffeIDFromSVID(svid)
		if err != nil {
			return nil, fmt.Errorf("cannot get spiffeID from SVID: %v. reqCount: %d", err, h.reqCount)
		}
		svids[spiffeID] = &node.Svid{SvidCert: svid.Raw, Ttl: int32(h.c.svidTTL)}
	}
	return svids, nil
}

func (h *mockNodeAPIHandler) countRequest() {
	h.reqCount++
}

func (h *mockNodeAPIHandler) FetchBaseSVID(context.Context, *node.FetchBaseSVIDRequest) (*node.FetchBaseSVIDResponse, error) {
	h.c.t.Fatalf("unexpected call to FetchBaseSVID")
	return nil, nil
}

func (h *mockNodeAPIHandler) FetchSVID(stream node.Node_FetchSVIDServer) error {
	h.countRequest()

	req, err := stream.Recv()
	if err != nil {
		return err
	}
	if h.c.fetchSVIDResponse != nil {
		return h.c.fetchSVIDResponse(h, req, stream)
	}
	return nil
}

func (h *mockNodeAPIHandler) FetchFederatedBundle(context.Context, *node.FetchFederatedBundleRequest) (*node.FetchFederatedBundleResponse, error) {
	h.c.t.Fatalf("unexpected call to FetchFederatedBundle")
	return nil, nil
}

func (h *mockNodeAPIHandler) start() {
	s := grpc.NewServer(h.creds)
	node.RegisterNodeServer(s, h)
	h.server = s

	l, err := net.Listen("unix", h.sockPath)
	if err != nil {
		h.c.t.Fatalf("create UDS listener: %s", err)
	}

	go func() {
		err := h.server.Serve(l)
		if err != nil {
			panic(fmt.Errorf("error starting mock server: %v", err))
		}
	}()

	// Let grpc server initialize
	time.Sleep(1 * time.Millisecond)
}

func (h *mockNodeAPIHandler) stop() {
	h.server.Stop()
	os.Remove(h.sockPath)
}

func (h *mockNodeAPIHandler) ca() *x509.Certificate {
	return h.bundle[len(h.bundle)-1]
}

func (h *mockNodeAPIHandler) newSVID(spiffeID string, ttl time.Duration) (*x509.Certificate, *ecdsa.PrivateKey) {
	return createSVID(h.c.t, h.ca(), h.cakey, spiffeID, ttl)
}

func (h *mockNodeAPIHandler) newSVIDFromCSR(csr []byte) *x509.Certificate {
	return createSVIDFromCSR(h.c.t, h.ca(), h.cakey, csr, h.c.svidTTL)
}

func (h *mockNodeAPIHandler) getGRPCServerConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	certChain := [][]byte{h.svid.Raw, h.ca().Raw}
	certs := []tls.Certificate{{
		Certificate: certChain,
		PrivateKey:  h.svidKey,
	}}

	roots := x509.NewCertPool()
	roots.AddCert(h.ca())

	c := &tls.Config{
		ClientAuth:   tls.RequestClientCert,
		Certificates: certs,
		ClientCAs:    roots,
	}

	return c, nil
}

func (h *mockNodeAPIHandler) getCertFromCtx(ctx context.Context) (certificate *x509.Certificate, err error) {

	ctxPeer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("It was not posible to extract peer from request")
	}
	tlsInfo, ok := ctxPeer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.New("It was not posible to extract AuthInfo from request")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, errors.New("PeerCertificates was empty")
	}

	return tlsInfo.State.PeerCertificates[0], nil
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

func createCA(t *testing.T, trustDomain string) (*x509.Certificate, *ecdsa.PrivateKey) {
	tmpl, err := util.NewCATemplate(trustDomain)
	if err != nil {
		t.Fatalf("cannot create ca template: %v", err)
	}

	ca, cakey, err := util.SelfSign(tmpl)
	if err != nil {
		t.Fatalf("cannot self sign ca template: %v", err)
	}
	return ca, cakey
}

func createSVID(t *testing.T, ca *x509.Certificate, cakey *ecdsa.PrivateKey, spiffeID string, ttl time.Duration) (*x509.Certificate, *ecdsa.PrivateKey) {
	tmpl, err := util.NewSVIDTemplate(spiffeID)
	if err != nil {
		t.Fatalf("cannot create svid template for %s: %v", spiffeID, err)
	}

	tmpl.NotAfter = tmpl.NotBefore.Add(ttl)

	svid, svidkey, err := util.Sign(tmpl, ca, cakey)
	if err != nil {
		t.Fatalf("cannot sign svid template for %s: %v", spiffeID, err)
	}
	return svid, svidkey
}

func createSVIDFromCSR(t *testing.T, ca *x509.Certificate, cakey *ecdsa.PrivateKey, csr []byte, ttl int) *x509.Certificate {
	tmpl, err := util.NewSVIDTemplateFromCSR(csr, ca, ttl)
	if err != nil {
		t.Fatalf("cannot create svid template from CSR: %v", err)
	}

	svid, _, err := util.Sign(tmpl, ca, cakey)
	if err != nil {
		t.Fatalf("cannot sign svid template for CSR: %v", err)
	}
	return svid
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
