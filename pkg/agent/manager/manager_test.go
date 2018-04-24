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
	"sync"
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

	m.Shutdown()
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

	// Sleep to ensure that rotation will happen
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

	m.Shutdown()
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

		svid := h.newSVIDFromCSR(req.Csrs[0], 200)
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

		svid1 := h.newSVIDFromCSR(req.Csrs[0], 200)
		spiffeID1, err := getSpiffeIDFromSVID(svid1)
		if err != nil {
			return err
		}

		svid2 := h.newSVIDFromCSR(req.Csrs[1], 200)
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

		svid := h.newSVIDFromCSR(req.Csrs[0], 3)
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

func newFetchSVIDResponse(regEntriesKey string, svids svidMap, ca *x509.Certificate) *node.FetchSVIDResponse {
	return &node.FetchSVIDResponse{
		SvidUpdate: &node.SvidUpdate{
			RegistrationEntries: regEntriesMap[regEntriesKey],
			Svids:               svids,
			Bundle:              ca.Raw,
		},
	}
}

func asMap(res []*common.RegistrationEntry) (result map[string]*common.RegistrationEntry) {
	result = map[string]*common.RegistrationEntry{}
	for _, re := range res {
		result[re.EntryId] = re
	}
	return result
}

func compareRegistrationEntries(t *testing.T, expected, actual []*common.RegistrationEntry) {
	if len(expected) != len(actual) {
		t.Errorf("entries count doesn't match, expected: %d, got: %d", len(expected), len(actual))
		return
	}

	expectedMap := asMap(expected)
	actualMap := asMap(actual)

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
}

type mockNodeAPIHandler struct {
	c *mockNodeAPIHandlerConfig

	ca    *x509.Certificate
	cakey *ecdsa.PrivateKey

	sockPath string
	server   *grpc.Server

	// Counts the number of requests received from clients
	reqCount int

	// Make sure this mock passes race tests
	mtx *sync.Mutex

	delay time.Duration
}

func newMockNodeAPIHandler(config *mockNodeAPIHandlerConfig) *mockNodeAPIHandler {
	ca, cakey := createCA(config.t, config.trustDomain)

	h := &mockNodeAPIHandler{
		c:        config,
		mtx:      new(sync.Mutex),
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

func (h *mockNodeAPIHandler) newSVIDFromCSR(csr []byte, ttl int) *x509.Certificate {
	return createSVIDFromCSR(h.c.t, h.ca, h.cakey, csr, ttl)
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

//
//func TestManager_FetchSVID(t *testing.T) {
//	ctrl := gomock.NewController(t)
//	defer ctrl.Finish()
//
//	var requests []entryRequest
//	requests = append(requests, testEntryRequest)
//	//var wg sync.WaitGroup
//
//	baseSVID, _ := x509.ParseCertificate(certsFixture.GetTestBaseSVID())
//	c := &Config{
//		ServerAddr:  &net.TCPAddr{},
//		SVID:        baseSVID,
//		SVIDKey:     baseSVIDKey,
//		Log:         testLogger,
//		TrustDomain: url.URL{},
//	}
//	m, _ := New(c)
//	stream := nodeMock.NewMockNode_FetchSVIDClient(ctrl)
//	stream.EXPECT().Send(gomock.Any()).Return(nil)
//	stream.EXPECT().Recv().Return(&node.FetchSVIDResponse{SvidUpdate: svidUpdate}, nil)
//	stream.EXPECT().CloseSend().Return(nil)
//	nodeClient := nodeMock.NewMockNodeClient(ctrl)
//	nodeClient.EXPECT().FetchSVID(gomock.Any()).Return(stream, nil)
//
//	m.Start()
//	m.Shutdown()
//	//cm.regEntriesCh = make(chan []*common.RegistrationEntry)
//
//	//wg.Add(1)
//	//go cm.fetchSVID(requests, nodeClient, &wg)
//
//	//cm.cacheEntryCh = make(chan Entry)
//
//	//<-cm.regEntriesCh
//	//entry := <-cm.cacheEntryCh
//	//cm.managedCache.SetEntry(entry)
//
//	//wg.Wait()
//	//expiry := cm.managedCache.Entry([]*common.Selector{
//	//	{Type: "unix", Value: "uid:111"},
//	//})[0].SVID.NotAfter
//
//	//TODO: review this
//	//assert.True(t, expiry.Equal(testCacheEntry.SVID.NotAfter))
//
//}
//
////func TestManager_ExpiredCacheEntryHandler(t *testing.T) {
////	cm := NewManager(
////		testCache, testServerCerts,
////		serverId, "fakeServerAddr",
////		errorCh, certsFixture.GetTestBaseSVID(), baseSVIDKey, regEntries, testLogger)
////	cm.entryRequestCh = make(chan map[string][]EntryRequest)
////	cm.spiffeIdEntryMap = make(map[string]CacheEntry)
////
////	stop := make(chan struct{})
////	go cm.expiredCacheEntryHandler(3000*time.Millisecond, stop)
////	cm.managedSetEntry(testCacheEntry)
////	entryRequest := <-cm.entryRequestCh
////	assert.NotEmpty(t, entryRequest[testCacheEntry.RegistrationEntry.ParentId])
////	stop <- struct{}{}
////
////}
//
//func TestManager_UpdateCache(t *testing.T) {
//	baseSVID, _ := x509.ParseCertificate(certsFixture.GetTestBaseSVID())
//	c := &Config{
//		ServerAddr: &net.TCPAddr{},
//		SVID:       baseSVID,
//		SVIDKey:    baseSVIDKey,
//		Log:        testLogger}
//	m, _ := New(c)
//	m.Start()
//	m.Shutdown()
//	//cm.Init()
//	//time.Sleep(1*time.Second)
//	//cm.cacheEntryCh = make(chan CacheEntry)
//	//cm.cacheEntryCh<-testCacheEntry
//	//assert.NotEmpty(t,cm.managedEntry([]*common.Selector{
//	//	&common.Selector{Type: "unix", Value: "uid:111"},
//	//}))
//	//cm.cancel()
//}

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
