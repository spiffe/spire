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
	"testing"
	"time"

	testlog "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/util"
	testutil "github.com/spiffe/spire/test/util"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const (
	tmpSubdirName = "manager-test"
)

var (
	testLogger, _ = testlog.NewNullLogger()
	regEntriesMap = testutil.GetRegistrationEntriesMap("manager_test_entries.json")
)

func TestShutdownDoesntHangAfterFailedStart(t *testing.T) {
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
		t.Error(err)
		return
	}

	err = m.Start()
	if err == nil {
		t.Fatal("wanted error")
	}

	util.RunWithTimeout(t, 1*time.Second, func() {
		m.Shutdown()
	})
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

	err = m.Start()
	if err == nil {
		t.Fatal("manager was expected to fail during startup")
	}

	// Althought start failed, the Bundle should have been saved, because it should be
	// one of the first thing the manager does at startup.
	bundle, err := ReadBundle(c.BundleCachePath)
	if err != nil {
		t.Fatalf("bundle should have been saved in a file: %v", err)
	}

	if !bundle[0].Equal(ca) {
		t.Fatal("bundle should have included CA certificate")
	}
	m.Shutdown()
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

	err = m.Start()
	if err == nil {
		t.Fatal("manager was expected to fail during startup")
	}

	// Althought start failed, the SVID should have been saved, because it should be
	// one of the first thing the manager does at startup.
	cert, err := ReadSVID(c.SVIDCachePath)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Equal(baseSVID) {
		t.Fatal("SVID was not correctly stored.")
	}

	m.Shutdown()
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
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}

	err = m.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()

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

	err = compareRegistrationEntries(
		regEntriesMap["resp2"],
		[]*common.RegistrationEntry{me[0].RegistrationEntry, me[1].RegistrationEntry})
	if err != nil {
		t.Fatal(err)
	}

	util.RunWithTimeout(t, 5*time.Second, func() {
		sub := m.NewSubscriber(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
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

		err := compareRegistrationEntries(
			regEntriesMap["resp2"],
			[]*common.RegistrationEntry{u.Entries[0].RegistrationEntry, u.Entries[1].RegistrationEntry})
		if err != nil {
			t.Fatal(err)
		}
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
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}

	err = m.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()

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

	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}

	err = m.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()

	sub := m.NewSubscriber(cache.Selectors{
		&common.Selector{Type: "unix", Value: "uid:1111"},
		&common.Selector{Type: "spiffe_id", Value: "spiffe://example.org/spire/agent/join_token/abcd"},
	})

	// Before synchronization
	entriesBefore := cacheEntriesAsMap(m.cache.Entries())
	if len(entriesBefore) != 3 {
		t.Fatal("3 cached entries were expected")
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
		<-sub.Updates()
		<-sub.Updates()
		u := <-sub.Updates()

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

	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}

	sub := m.NewSubscriber(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})

	err = m.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()

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

	m, err := New(c)
	if err != nil {
		t.Error(err)
		return
	}

	sub := m.NewSubscriber(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
	// This should be the update received when Subscribe function was called.
	<-sub.Updates()

	err = m.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown()

	// Get latest update
	util.RunWithTimeout(t, 4*time.Second, func() {
		<-sub.Updates()
	})

	// Wait update, it should be received once connection is restablished by synchronization
	elapsed := util.RunWithTimeout(t, 8*time.Second, func() {
		<-sub.Updates()
	})

	// If we received an update too soon, then we assume that the connection to the server never
	// was lost and hence we are not testing if the manager can survive the CA rotation.
	if elapsed < 3*time.Second {
		t.Fatalf("update received too soon: elapsed %dms since last one", elapsed/time.Millisecond)
	}
}

func fetchSVIDResponseForTestHappyPathWithoutSyncNorRotation(h *mockNodeAPIHandler, req *node.FetchSVIDRequest, stream node.Node_FetchSVIDServer) error {
	switch h.reqCount {
	case 1:
		if len(req.Csrs) != 0 {
			return fmt.Errorf("server expected 0 CRS, got: %d. reqCount: %d", len(req.Csrs), h.reqCount)
		}

		return stream.Send(newFetchSVIDResponse("resp1", nil, h.bundle))
	case 2:
		if len(req.Csrs) != 1 {
			return fmt.Errorf("server expected 1 CRS, got: %d. reqCount: %d", len(req.Csrs), h.reqCount)
		}

		svid := h.newSVIDFromCSR(req.Csrs[0])
		spiffeID, err := getSpiffeIDFromSVID(svid)
		if err != nil {
			return err
		}

		return stream.Send(newFetchSVIDResponse(
			"resp1",
			svidMap{
				spiffeID: {SvidCert: svid.Raw},
			},
			h.bundle))
	case 3:
		if len(req.Csrs) != 0 {
			return fmt.Errorf("server expected 0 CRS, got: %d. reqCount: %d", len(req.Csrs), h.reqCount)
		}

		return stream.Send(newFetchSVIDResponse("resp2", nil, h.bundle))
	case 4:
		if len(req.Csrs) != 2 {
			return fmt.Errorf("server expected 2 CRS, got: %d. reqCount: %d", len(req.Csrs), h.reqCount)
		}

		svid1 := h.newSVIDFromCSR(req.Csrs[0])
		spiffeID1, err := getSpiffeIDFromSVID(svid1)
		if err != nil {
			return err
		}

		svid2 := h.newSVIDFromCSR(req.Csrs[1])
		spiffeID2, err := getSpiffeIDFromSVID(svid2)
		if err != nil {
			return err
		}

		return stream.Send(newFetchSVIDResponse(
			"resp2",
			svidMap{
				spiffeID1: {SvidCert: svid1.Raw},
				spiffeID2: {SvidCert: svid2.Raw},
			},
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

	resp := "resp0"
	switch spiffeID {
	case "spiffe://example.org/spire/agent/join_token/abcd":
		resp = "resp1"
	case "spiffe://example.org/spire/agent":
		resp = "resp2"
	}

	svids := map[string]*node.Svid{}
	for _, csr := range req.Csrs {
		svid := h.newSVIDFromCSR(csr)
		spiffeID, err := getSpiffeIDFromSVID(svid)
		if err != nil {
			return fmt.Errorf("cannot get spiffeID from SVID: %v. reqCount: %d", err, h.reqCount)
		}
		svids[spiffeID] = &node.Svid{SvidCert: svid.Raw, Ttl: int32(h.c.svidTTL)}
	}

	return stream.Send(newFetchSVIDResponse(resp, svids, h.bundle))
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

func newFetchSVIDResponse(regEntriesKey string, svids svidMap, bundle []*x509.Certificate) *node.FetchSVIDResponse {
	bundleBytes := &bytes.Buffer{}
	for _, c := range bundle {
		bundleBytes.Write(c.Raw)
	}

	return &node.FetchSVIDResponse{
		SvidUpdate: &node.SvidUpdate{
			RegistrationEntries: regEntriesMap[regEntriesKey],
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

func compareRegistrationEntries(expected, actual []*common.RegistrationEntry) error {
	if len(expected) != len(actual) {
		return fmt.Errorf("entries count doesn't match, expected: %d, got: %d", len(expected), len(actual))
	}

	expectedMap := regEntriesAsMap(expected)
	actualMap := regEntriesAsMap(actual)

	for id, ee := range expectedMap {
		ae, ok := actualMap[id]
		if !ok {
			return fmt.Errorf("entries should be equals, expected: %s, got: <none>", ee.String())
		}

		if ee.String() != ae.String() {
			return fmt.Errorf("entries should be equals, expected: %s, got: %s", ee.String(), ae.String())
		}
	}
	return nil
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
		serverID: "spiffe://" + config.trustDomain + "/spiffe/server",
	}

	h.svid, h.svidKey = h.newSVID(h.serverID, 1*time.Hour)

	tlsConfig := &tls.Config{
		GetConfigForClient: h.getGRPCServerConfig,
	}

	h.creds = grpc.Creds(credentials.NewTLS(tlsConfig))
	return h
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
