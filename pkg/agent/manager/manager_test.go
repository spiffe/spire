package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"net"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	testlog "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	certsFixture "github.com/spiffe/spire/test/fixture/certs"
	nodeMock "github.com/spiffe/spire/test/mock/proto/api/node"
	testutil "github.com/spiffe/spire/test/util"
)

var (
	testServerCerts = []*x509.Certificate{{}, {}}
	baseSVIDKey, _  = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	testLogger, _   = testlog.NewNullLogger()
	regEntries      = testutil.GetRegistrationEntries("good.json")
	blogSVID, _     = x509.ParseCertificate(certsFixture.GetTestBlogSVID())

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
		CSR:   certsFixture.GetTestBlogCSR(),
		entry: testCacheEntry,
	}

	svidMap = map[string]*node.Svid{
		"spiffe://example.org/Blog": {SvidCert: certsFixture.GetTestBlogSVID()}}

	svidUpdate = &node.SvidUpdate{
		Svids:               svidMap,
		RegistrationEntries: testutil.GetRegistrationEntries("good.json"),
	}
)

func TestManager_FetchSVID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var requests []entryRequest
	requests = append(requests, testEntryRequest)
	//var wg sync.WaitGroup

	baseSVID, _ := x509.ParseCertificate(certsFixture.GetTestBaseSVID())
	c := &Config{
		ServerAddr:  &net.TCPAddr{},
		SVID:        baseSVID,
		SVIDKey:     baseSVIDKey,
		Log:         testLogger,
		TrustDomain: url.URL{},
	}
	m, _ := New(c)
	stream := nodeMock.NewMockNode_FetchSVIDClient(ctrl)
	stream.EXPECT().Send(gomock.Any()).Return(nil)
	stream.EXPECT().Recv().Return(&node.FetchSVIDResponse{SvidUpdate: svidUpdate}, nil)
	stream.EXPECT().CloseSend().Return(nil)
	nodeClient := nodeMock.NewMockNodeClient(ctrl)
	nodeClient.EXPECT().FetchSVID(gomock.Any()).Return(stream, nil)

	m.Start()
	m.Shutdown()
	//cm.regEntriesCh = make(chan []*common.RegistrationEntry)

	//wg.Add(1)
	//go cm.fetchSVID(requests, nodeClient, &wg)

	//cm.cacheEntryCh = make(chan Entry)

	//<-cm.regEntriesCh
	//entry := <-cm.cacheEntryCh
	//cm.managedCache.SetEntry(entry)

	//wg.Wait()
	//expiry := cm.managedCache.Entry([]*common.Selector{
	//	{Type: "unix", Value: "uid:111"},
	//})[0].SVID.NotAfter

	//TODO: review this
	//assert.True(t, expiry.Equal(testCacheEntry.SVID.NotAfter))

}

func TestManager_RegEntriesHandler(t *testing.T) {
	baseSVID, _ := x509.ParseCertificate(certsFixture.GetTestBaseSVID())
	c := &Config{
		ServerAddr: &net.TCPAddr{},
		SVID:       baseSVID,
		SVIDKey:    baseSVIDKey,
		Log:        testLogger}
	m, _ := New(c)
	m.Start()
	m.Shutdown()
	//cm.regEntriesCh = make(chan []*common.RegistrationEntry)
	//wg.Add(1)
	//go cm.regEntriesHandler(&wg)
	//cm.entryRequestCh = make(chan map[string][]EntryRequest)

	//cm.regEntriesCh <- regEntries
	//entryRequests := <-cm.entryRequestCh
	//for _, regEntry := range regEntries {
	//	assert.NotEmpty(t, entryRequests[regEntry.ParentId])
	//}
	//cm.cancel()
	//wg.Wait()
}

//func TestManager_ExpiredCacheEntryHandler(t *testing.T) {
//	cm := NewManager(
//		testCache, testServerCerts,
//		serverId, "fakeServerAddr",
//		errorCh, certsFixture.GetTestBaseSVID(), baseSVIDKey, regEntries, testLogger)
//	cm.entryRequestCh = make(chan map[string][]EntryRequest)
//	cm.spiffeIdEntryMap = make(map[string]CacheEntry)
//
//	stop := make(chan struct{})
//	go cm.expiredCacheEntryHandler(3000*time.Millisecond, stop)
//	cm.managedSetEntry(testCacheEntry)
//	entryRequest := <-cm.entryRequestCh
//	assert.NotEmpty(t, entryRequest[testCacheEntry.RegistrationEntry.ParentId])
//	stop <- struct{}{}
//
//}

func TestManager_UpdateCache(t *testing.T) {
	baseSVID, _ := x509.ParseCertificate(certsFixture.GetTestBaseSVID())
	c := &Config{
		ServerAddr: &net.TCPAddr{},
		SVID:       baseSVID,
		SVIDKey:    baseSVIDKey,
		Log:        testLogger}
	m, _ := New(c)
	m.Start()
	m.Shutdown()
	//cm.Init()
	//time.Sleep(1*time.Second)
	//cm.cacheEntryCh = make(chan CacheEntry)
	//cm.cacheEntryCh<-testCacheEntry
	//assert.NotEmpty(t,cm.managedEntry([]*common.Selector{
	//	&common.Selector{Type: "unix", Value: "uid:111"},
	//}))
	//cm.cancel()
}
