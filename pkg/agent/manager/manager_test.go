package manager

import (
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

	"github.com/sirupsen/logrus"
	testlog "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/util"
	testutil "github.com/spiffe/spire/test/util"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	tmpSubdirName = "manager-test"
)

var (
	testLogger, _ = testlog.NewNullLogger()
	regEntriesMap = testutil.GetRegistrationEntriesMap("manager_test_entries.json")
)

func TestManager_ShutdownDoesntHangAfterFailedStart(t *testing.T) {
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
		t.Errorf("wanted error")
		return
	}

	util.RunWithTimeout(t, 1*time.Second, func() {
		m.Shutdown()
	})
}

func TestManager_StoreSVIDOnStartup(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	trustDomain := "somedomain.com"
	ca, cakey := createCA(t, trustDomain)
	baseSVID, baseSVIDKey := createSVID(t, ca, cakey, "spiffe://"+trustDomain+"/agent", 1*time.Hour)

	c := &Config{
		ServerAddr:    &net.TCPAddr{},
		SVID:          baseSVID,
		SVIDKey:       baseSVIDKey,
		Log:           testLogger,
		TrustDomain:   url.URL{Host: "somedomain.com"},
		SVIDCachePath: path.Join(dir, "svid.der"),
	}

	_, err := ReadSVID(c.SVIDCachePath)
	if err != ErrNotCached {
		t.Errorf("wanted: %v, got: %v", ErrNotCached, err)
		return
	}

	m, err := New(c)
	if err != nil {
		t.Error(err)
		return
	}

	err = m.Start()
	if err != nil {
		// Althought start failed, the SVID should have been saved, because it should be
		// the first thing the manager does at startup.
		cert, err := ReadSVID(c.SVIDCachePath)
		if err != nil {
			t.Error(err)
			return
		}
		if !cert.Equal(baseSVID) {
			t.Error("SVID was not correctly stored.")
			return
		}
	}

	m.Shutdown()
	os.Remove(c.SVIDCachePath)
}

func TestManager_HappyPath(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	trustDomain := "example.org"

	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:                 t,
		trustDomain:       trustDomain,
		dir:               dir,
		fetchSVIDResponse: fetchSVIDResponse_HappyPath,
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
		SVID:          baseSVID,
		SVIDKey:       baseSVIDKey,
		Log:           logrus.New(),
		TrustDomain:   url.URL{Host: trustDomain},
		SVIDCachePath: path.Join(dir, "svid.der"),
		Bundle:        []*x509.Certificate{apiHandler.ca},
		Tel:           &telemetry.Blackhole{},
	}
	mgr, err := New(c)
	if err != nil {
		t.Error(err)
		return
	}

	m := mgr.(*manager)
	err = m.Start()
	if err != nil {
		t.Error(err)
		return
	}
	defer m.Shutdown()

	cert, key := m.getBaseSVIDEntry()
	if !cert.Equal(baseSVID) {
		t.Error("SVID is not equals to configured one")
	}
	if key != baseSVIDKey {
		t.Error("PrivateKey is not equals to configured one")
	}

	me := m.MatchingEntries(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}})
	if len(me) != 2 {
		t.Error("expected 2 entries")
	}

	compareRegistrationEntries(t,
		regEntriesMap["resp2"],
		[]*common.RegistrationEntry{me[0].RegistrationEntry, me[1].RegistrationEntry})

	util.RunWithTimeout(t, 1*time.Second, func() {
		done := make(chan struct{})
		wu := m.Subscribe(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}}, done)
		u := <-wu

		if len(u.Entries) != 2 {
			t.Error("expected 2 entries")
		}

		if len(u.Bundle) != 1 {
			t.Error("expected 1 bundle")
		}

		if !u.Bundle[0].Equal(apiHandler.ca) {
			t.Error("received bundle should be equals to the server bundle")
		}

		compareRegistrationEntries(t,
			regEntriesMap["resp2"],
			[]*common.RegistrationEntry{u.Entries[0].RegistrationEntry, u.Entries[1].RegistrationEntry})
	})
}

func TestManager_SVIDRotation(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	trustDomain := "example.org"

	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:                 t,
		trustDomain:       trustDomain,
		dir:               dir,
		fetchSVIDResponse: fetchSVIDResponse_SVIDRotation,
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
		SVID:          baseSVID,
		SVIDKey:       baseSVIDKey,
		Log:           logrus.New(),
		TrustDomain:   url.URL{Host: trustDomain},
		SVIDCachePath: path.Join(dir, "svid.der"),
		Bundle:        []*x509.Certificate{apiHandler.ca},
		Tel:           &telemetry.Blackhole{},
	}
	mgr, err := New(c)
	if err != nil {
		t.Error(err)
		return
	}

	m := mgr.(*manager)
	m.rotationFreq = baseTTL / 2
	m.syncFreq = 1 * time.Hour
	err = m.Start()
	if err != nil {
		t.Error(err)
		return
	}
	defer m.Shutdown()

	elapsed := time.Since(baseSVID.NotBefore)
	if elapsed > 2*baseTTL/3 {
		t.Errorf("manager startup took too long: %dms", elapsed/time.Millisecond)
		return
	}

	cert, key := m.getBaseSVIDEntry()
	if !cert.Equal(baseSVID) {
		t.Error("SVID is not equals to configured one")
		return
	}
	if key != baseSVIDKey {
		t.Error("PrivateKey is not equals to configured one")
		return
	}

	// Sleep to ensure that rotation happened
	time.Sleep(baseTTL - elapsed)

	cert, key = m.getBaseSVIDEntry()
	if cert.Equal(baseSVID) {
		t.Error("SVID did not rotate")
		return
	}
	if key == baseSVIDKey {
		t.Error("PrivateKey did not rotate")
		return
	}
}

func TestManager_Synchronization(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	trustDomain := "example.org"

	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:                 t,
		trustDomain:       trustDomain,
		dir:               dir,
		fetchSVIDResponse: fetchSVIDResponse_Synchronization,
		svidTTL:           2,
	})
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://"+trustDomain+"/spire/agent/join_token/abcd", 1*time.Hour)

	c := &Config{
		ServerAddr: &net.UnixAddr{
			Net:  "unix",
			Name: apiHandler.sockPath,
		},
		SVID:          baseSVID,
		SVIDKey:       baseSVIDKey,
		Log:           logrus.New(),
		TrustDomain:   url.URL{Host: trustDomain},
		SVIDCachePath: path.Join(dir, "svid.der"),
		Bundle:        []*x509.Certificate{apiHandler.ca},
		Tel:           &telemetry.Blackhole{},
	}
	mgr, err := New(c)
	if err != nil {
		t.Error(err)
		return
	}

	m := mgr.(*manager)
	m.rotationFreq = 1 * time.Hour
	m.syncFreq = 2 * time.Second
	start := time.Now()
	err = m.Start()
	if err != nil {
		t.Error(err)
		return
	}
	defer m.Shutdown()

	done := make(chan struct{})
	wu := m.Subscribe(cache.Selectors{&common.Selector{Type: "unix", Value: "uid:1111"}}, done)

	// Before synchronization
	entriesBefore := cacheEntriesAsMap(m.cache.Entries())
	if len(entriesBefore) != 3 {
		t.Error("3 cached entries were expected")
		return
	}

	// If synchronization could already have happened, we cannot continue with this test.
	elapsed := time.Since(start)
	if elapsed > m.syncFreq {
		t.Errorf("manager startup took too long: %dms", elapsed/time.Millisecond)
		return
	}

	util.RunWithTimeout(t, 1*time.Second, func() {
		u := <-wu

		if len(u.Entries) != 2 {
			t.Error("expected 2 entries")
		}

		if len(u.Bundle) != 1 {
			t.Error("expected 1 bundle")
		}

		if !u.Bundle[0].Equal(apiHandler.ca) {
			t.Error("received bundle should be equals to the server bundle")
		}

		compareRegistrationEntries(t,
			regEntriesMap["resp2"],
			[]*common.RegistrationEntry{u.Entries[0].RegistrationEntry, u.Entries[1].RegistrationEntry})

		entriesUpdated := cacheEntriesAsMap(u.Entries)
		for key, eu := range entriesUpdated {
			eb, ok := entriesBefore[key]
			if !ok {
				t.Errorf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
				return
			}
			if eb != eu {
				t.Error("entry received does not match entry on cache")
				return
			}
		}
	})

	// Wait until next update to ensure that sync happened. After
	// sync it should be 2 updates, here we consume one.
	util.RunWithTimeout(t, 2*m.syncFreq-elapsed, func() {
		<-wu
	})

	entriesAfter := cacheEntriesAsMap(m.cache.Entries())
	if len(entriesAfter) != 3 {
		t.Error("3 cached entries were expected")
		return
	}

	util.RunWithTimeout(t, 1*time.Second, func() {
		// Here we cosume the second update after sync.
		u := <-wu
		close(done)

		if len(u.Entries) != 2 {
			t.Error("expected 2 entries")
		}

		if len(u.Bundle) != 1 {
			t.Error("expected 1 bundle")
		}

		if !u.Bundle[0].Equal(apiHandler.ca) {
			t.Error("received bundle should be equals to the server bundle")
		}

		compareRegistrationEntries(t,
			regEntriesMap["resp2"],
			[]*common.RegistrationEntry{u.Entries[0].RegistrationEntry, u.Entries[1].RegistrationEntry})

		entriesUpdated := cacheEntriesAsMap(u.Entries)
		for key, eu := range entriesUpdated {
			ea, ok := entriesAfter[key]
			if !ok {
				t.Errorf("an update was received for an inexistent entry on the cache with EntryId=%v", key)
				return
			}
			if ea != eu {
				t.Error("entry received does not match entry on cache")
				return
			}
		}
	})

	for key, eb := range entriesBefore {
		ea, ok := entriesAfter[key]
		if !ok {
			t.Errorf("expected entry with EntryId=%v after synchronization", key)
			return
		}
		if ea == eb {
			t.Error("there is at least one entry that was not refreshed")
			return
		}
	}
}

func fetchSVIDResponse_HappyPath(h *mockNodeAPIHandler, req *node.FetchSVIDRequest, stream node.Node_FetchSVIDServer) error {
	switch h.reqCount {
	case 1:
		if len(req.Csrs) != 0 {
			return fmt.Errorf("server expected 0 CRS, got: %d", len(req.Csrs))
		}

		return stream.Send(newFetchSVIDResponse("resp1", nil, h.ca))
	case 2:
		if len(req.Csrs) != 1 {
			return fmt.Errorf("server expected 1 CRS, got: %d", len(req.Csrs))
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
			h.ca))
	case 3:
		if len(req.Csrs) != 0 {
			return fmt.Errorf("server expected 0 CRS, got: %d", len(req.Csrs))
		}

		return stream.Send(newFetchSVIDResponse("resp2", nil, h.ca))
	case 4:
		if len(req.Csrs) != 2 {
			return fmt.Errorf("server expected 2 CRS, got: %d", len(req.Csrs))
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
			h.ca))
	default:
		return errors.New("server received unexpected call")
	}
}

func fetchSVIDResponse_SVIDRotation(h *mockNodeAPIHandler, req *node.FetchSVIDRequest, stream node.Node_FetchSVIDServer) error {
	switch h.reqCount {
	case 5:
		if len(req.Csrs) != 1 {
			return fmt.Errorf("server expected 1 CRS, got: %d", len(req.Csrs))
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
			h.ca))
	default:
		return fetchSVIDResponse_HappyPath(h, req, stream)
	}
}

func fetchSVIDResponse_Synchronization(h *mockNodeAPIHandler, req *node.FetchSVIDRequest, stream node.Node_FetchSVIDServer) error {
	switch h.reqCount {
	case 5:
		if len(req.Csrs) != 0 {
			return fmt.Errorf("server expected 0 CRS, got: %d", len(req.Csrs))
		}

		return stream.Send(newFetchSVIDResponse("resp1", nil, h.ca))
	case 6:
		if len(req.Csrs) != 0 {
			return fmt.Errorf("server expected 0 CRS, got: %d", len(req.Csrs))
		}

		return stream.Send(newFetchSVIDResponse("resp2", nil, h.ca))
	case 7:
		if len(req.Csrs) != 1 {
			return fmt.Errorf("server expected 1 CRS, got: %d", len(req.Csrs))
		}

		svid := h.newSVIDFromCSR(req.Csrs[0])
		spiffeID, err := getSpiffeIDFromSVID(svid)
		if err != nil {
			return err
		}

		return stream.Send(newFetchSVIDResponse(
			"resp2",
			svidMap{
				spiffeID: {SvidCert: svid.Raw},
			},
			h.ca))
	case 8:
		if len(req.Csrs) != 2 {
			return fmt.Errorf("server expected 2 CRS, got: %d", len(req.Csrs))
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
			"resp0",
			svidMap{
				spiffeID1: {SvidCert: svid1.Raw},
				spiffeID2: {SvidCert: svid2.Raw},
			},
			h.ca))
	case 9:
		if len(req.Csrs) != 0 {
			return fmt.Errorf("server expected 0 CRS, got: %d", len(req.Csrs))
		}

		return stream.Send(newFetchSVIDResponse("resp2", nil, h.ca))
	default:
		return fetchSVIDResponse_HappyPath(h, req, stream)
	}
}

func newFetchSVIDResponse(regEntriesKey string, svids svidMap, ca *x509.Certificate) *node.FetchSVIDResponse {
	return &node.FetchSVIDResponse{
		SvidUpdate: &node.SvidUpdate{
			RegistrationEntries: regEntriesMap[regEntriesKey],
			Svids:               svids,
			Bundle:              ca.Raw,
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

func compareRegistrationEntries(t *testing.T, expected, actual []*common.RegistrationEntry) {
	if len(expected) != len(actual) {
		t.Errorf("entries count doesn't match, expected: %d, got: %d", len(expected), len(actual))
		return
	}

	expectedMap := regEntriesAsMap(expected)
	actualMap := regEntriesAsMap(actual)

	for id, ee := range expectedMap {
		ae, ok := actualMap[id]
		if !ok {
			t.Errorf("entries should be equals, expected: %s, got: <none>", ee.String())
			return
		}

		if ee.String() != ae.String() {
			t.Errorf("entries should be equals, expected: %s, got: %s", ee.String(), ae.String())
			return
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

	ca    *x509.Certificate
	cakey *ecdsa.PrivateKey

	sockPath string
	server   *grpc.Server

	// Counts the number of requests received from clients
	reqCount int

	delay time.Duration
}

func newMockNodeAPIHandler(config *mockNodeAPIHandlerConfig) *mockNodeAPIHandler {
	ca, cakey := createCA(config.t, config.trustDomain)

	h := &mockNodeAPIHandler{
		c:        config,
		ca:       ca,
		cakey:    cakey,
		sockPath: path.Join(config.dir, "node_api.sock"),
	}

	serverSVID, serverSVIDKey := h.newSVID("spiffe://"+config.trustDomain+"/spiffe/server", 1*time.Hour)
	opts := grpc.Creds(h.newTLS(serverSVID, serverSVIDKey))
	s := grpc.NewServer(opts)

	node.RegisterNodeServer(s, h)
	h.server = s
	return h
}

func (h *mockNodeAPIHandler) countRequest() {
	h.reqCount++
}

func (h *mockNodeAPIHandler) FetchBaseSVID(context.Context, *node.FetchBaseSVIDRequest) (*node.FetchBaseSVIDResponse, error) {
	h.countRequest()
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
	h.countRequest()
	return nil, nil
}

func (h *mockNodeAPIHandler) start() {
	l, err := net.Listen("unix", h.sockPath)
	if err != nil {
		h.c.t.Fatalf("create UDS listener: %s", err)
	}

	go func() { h.server.Serve(l) }()

	// Let grpc server initialize
	time.Sleep(1 * time.Millisecond)
}

func (h *mockNodeAPIHandler) stop() {
	h.server.Stop()
	os.RemoveAll(path.Dir(h.sockPath))
}

func (h *mockNodeAPIHandler) newSVID(spiffeID string, ttl time.Duration) (*x509.Certificate, *ecdsa.PrivateKey) {
	return createSVID(h.c.t, h.ca, h.cakey, spiffeID, ttl)
}

func (h *mockNodeAPIHandler) newSVIDFromCSR(csr []byte) *x509.Certificate {
	return createSVIDFromCSR(h.c.t, h.ca, h.cakey, csr, h.c.svidTTL)
}

func (h *mockNodeAPIHandler) newTLS(svid *x509.Certificate, key *ecdsa.PrivateKey) credentials.TransportCredentials {
	certChain := [][]byte{svid.Raw, h.ca.Raw}
	tlsCert := []tls.Certificate{{
		Certificate: certChain,
		PrivateKey:  key,
	}}

	roots := x509.NewCertPool()
	roots.AddCert(h.ca)

	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequestClientCert,
		Certificates: tlsCert,
		ClientCAs:    roots,
	}
	return credentials.NewTLS(tlsConfig)
}

func createTempDir(t *testing.T) string {
	dir, err := ioutil.TempDir("", tmpSubdirName)
	if err != nil {
		t.Errorf("could not create temp dir: %v", err)
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
