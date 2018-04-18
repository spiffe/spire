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
	//testServerCerts = []*x509.Certificate{{}, {}}
	//baseSVIDKey, _  = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	testLogger, _ = testlog.NewNullLogger()
	regEntriesMap = testutil.GetRegistrationEntriesMap("manager_test_entries.json")
	/*
		blogSVID, _   = util.LoadBlogSVID()

		testCacheEntry = &cache.Entry{
			RegistrationEntry: &common.RegistrationEntry{
				SpiffeId: "spiffe://example.org/Blog",
				ParentId: "spiffe://example.org/spire/agent/join_token/TokenBlog",
				Selectors: []*common.Selector{
					{Type: "unix", Value: "uid:111"},
				},
				Ttl: 200,
			},
			SVID: blogSVID,
		}
		testEntryRequest = entryRequest{
			CSR:   util.LoadBlogCSRBytes(),
			entry: testCacheEntry,
		}

		svidMap = map[string]*node.Svid{
			"spiffe://example.org/Blog": {SvidCert: blogSVID.Raw}}

		svidUpdate = &node.SvidUpdate{
			Svids:               svidMap,
			RegistrationEntries: testutil.GetRegistrationEntries("good.json"),
		}
	*/
)

func TestManager_ShutdownDoesntHangAfterFailedStart(t *testing.T) {
	trustDomain := "somedomain.com"
	ca, cakey := createCA(t, trustDomain)
	baseSVID, baseSVIDKey := createSVID(t, ca, cakey, "spiffe://"+trustDomain+"/agent")

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
	baseSVID, baseSVIDKey := createSVID(t, ca, cakey, "spiffe://"+trustDomain+"/agent")

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

func TestManager_(t *testing.T) {
	dir := createTempDir(t)
	defer removeTempDir(dir)

	trustDomain := "example.org"

	apiHandler := newMockNodeAPIHandler(&mockNodeAPIHandlerConfig{
		t:                 t,
		trustDomain:       trustDomain,
		dir:               dir,
		fetchSVIDResponse: fetchSVIDResponse_,
	})
	apiHandler.start()
	defer apiHandler.stop()

	baseSVID, baseSVIDKey := apiHandler.newSVID("spiffe://" + trustDomain + "/spire/agent/join_token/abcd")

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
	//m.syncFreq = 100000000

	err = m.Start()
	if err != nil {
		t.Error(err)
		return
	}

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

		//u.Entries[0]
	})

	/*
	   ReceiveUpdates:
	   	for {
	   		select {
	   		case u := <-wu:
	   			fmt.Printf("%v", u.Entries[0])
	   		case <-done:
	   			break ReceiveUpdates
	   		}
	   	}
	*/
	m.Shutdown()

	//	//cm.regEntriesCh = make(chan []*common.RegistrationEntry)
	//	//wg.Add(1)
	//	//go cm.regEntriesHandler(&wg)
	//	//cm.entryRequestCh = make(chan map[string][]EntryRequest)
	//
	//	//cm.regEntriesCh <- regEntries
	//	//entryRequests := <-cm.entryRequestCh
	//	//for _, regEntry := range regEntries {
	//	//	assert.NotEmpty(t, entryRequests[regEntry.ParentId])
	//	//}
	//	//cm.cancel()
	//	//wg.Wait()
}

func fetchSVIDResponse_(h *mockNodeAPIHandler, req *node.FetchSVIDRequest, stream node.Node_FetchSVIDServer) error {
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

func newFetchSVIDResponse(regEntriesKey string, svids svidMap, ca *x509.Certificate) *node.FetchSVIDResponse {
	return &node.FetchSVIDResponse{
		SvidUpdate: &node.SvidUpdate{
			RegistrationEntries: regEntriesMap[regEntriesKey],
			Svids:               svids,
			Bundle:              ca.Raw,
		},
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

	serverSVID, serverSVIDKey := h.newSVID("spiffe://" + config.trustDomain + "/spiffe/cp")
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

func (h *mockNodeAPIHandler) newSVID(spiffeID string) (*x509.Certificate, *ecdsa.PrivateKey) {
	return createSVID(h.c.t, h.ca, h.cakey, spiffeID)
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

func createSVID(t *testing.T, ca *x509.Certificate, cakey *ecdsa.PrivateKey, spiffeID string) (*x509.Certificate, *ecdsa.PrivateKey) {
	tmpl, err := util.NewSVIDTemplate(spiffeID)
	if err != nil {
		t.Fatalf("cannot create svid template for %s: %v", spiffeID, err)
	}

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
