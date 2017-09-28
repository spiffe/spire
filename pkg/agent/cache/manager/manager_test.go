package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"github.com/golang/mock/gomock"
	testlog "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/cache"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	certsFixture "github.com/spiffe/spire/test/fixture/certs"
	regFixture "github.com/spiffe/spire/test/fixture/registration"
	nodeMock "github.com/spiffe/spire/test/mock/proto/api/node"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"time"
)

var (
	testCache       = cache.NewCache()
	testServerCerts = []*x509.Certificate{&x509.Certificate{}, &x509.Certificate{}}
	serverId        = "spiffe://testDomain/spiffe/cp"
	baseSVIDKey, _  = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	testLogger, _   = testlog.NewNullLogger()
	regEntries      = regFixture.GetRegistrationEntries()

	testCacheEntry = cache.CacheEntry{RegistrationEntry: &common.RegistrationEntry{
		SpiffeId: "spiffe://example.org/Blog",
		ParentId: "spiffe://example.org/spire/agent/join_token/TokenBlog",
		Selectors: []*common.Selector{
			&common.Selector{Type: "unix", Value: "uid:111"},
		},
		Ttl: 200,
	},
		SVID:   &node.Svid{SvidCert: certsFixture.GetTestBlogSVID()},
		Expiry: time.Now(),
	}
	testEntryRequest = EntryRequest{
		CSR:   certsFixture.GetTestBlogCSR(),
		entry: testCacheEntry,
	}

	svidMap = map[string]*node.Svid{
		"spiffe://example.org/Blog": &node.Svid{SvidCert: certsFixture.GetTestBlogSVID()}}

	svidUpdate = &node.SvidUpdate{
		Svids:               svidMap,
		RegistrationEntries: regFixture.GetRegistrationEntries()}
	errorCh = make(chan error)
)

func TestManager_FetchSVID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var requests []EntryRequest
	requests = append(requests, testEntryRequest)
	var wg sync.WaitGroup
	cm := NewManager(
		testCache, testServerCerts,
		serverId, "fakeServerAddr",
		errorCh, certsFixture.GetTestBaseSVID(), baseSVIDKey, regEntries, testLogger)

	stream := nodeMock.NewMockNode_FetchSVIDClient(ctrl)
	stream.EXPECT().Send(gomock.Any()).Return(nil)
	stream.EXPECT().Recv().Return(&node.FetchSVIDResponse{SvidUpdate: svidUpdate}, nil)
	nodeClient := nodeMock.NewMockNodeClient(ctrl)
	nodeClient.EXPECT().FetchSVID(gomock.Any()).Return(stream, nil)
	cm.regEntriesCh = make(chan []*common.RegistrationEntry)

	wg.Add(1)
	go cm.fetchSVID(requests, nodeClient, &wg)

	cm.CacheEntryCh = make(chan cache.CacheEntry)

	<-cm.regEntriesCh
	entry := <-cm.CacheEntryCh
	cm.managedCache.SetEntry(entry)

	wg.Wait()
	expiry := cm.managedCache.Entry([]*common.Selector{
		&common.Selector{Type: "unix", Value: "uid:111"},
	})[0].Expiry

	assert.True(t, expiry.After(testCacheEntry.Expiry))

}

func TestManager_RegEntriesHandler(t *testing.T) {
	cm := NewManager(
		testCache, testServerCerts,
		serverId, "fakeServerAddr",
		errorCh, certsFixture.GetTestBaseSVID(), baseSVIDKey, regEntries, testLogger)
	cm.regEntriesCh = make(chan []*common.RegistrationEntry)
	stop := make(chan struct{})
	go cm.regEntriesHandler(stop)
	cm.entryRequestCh = make(chan map[string][]EntryRequest)

	cm.regEntriesCh <- regEntries
	entryRequests := <-cm.entryRequestCh
	for _, regEntry := range regEntries {
		assert.NotEmpty(t, entryRequests[regEntry.ParentId])
	}
	stop <- struct{}{}
}

//func TestManager_ExpiredCacheEntryHandler(t *testing.T) {
//	cm := NewManager(
//		testCache, testServerCerts,
//		serverId, "fakeServerAddr",
//		errorCh, certsFixture.GetTestBaseSVID(), baseSVIDKey, regEntries, testLogger)
//	cm.entryRequestCh = make(chan map[string][]EntryRequest)
//	cm.spiffeIdEntryMap = make(map[string]cache.CacheEntry)
//
//	stop := make(chan struct{})
//	go cm.expiredCacheEntryHandler(3000*time.Millisecond, stop)
//	cm.managedCache.SetEntry(testCacheEntry)
//	entryRequest := <-cm.entryRequestCh
//	assert.NotEmpty(t, entryRequest[testCacheEntry.RegistrationEntry.ParentId])
//	stop <- struct{}{}
//
//}



func TestManager_UpdateCache(t *testing.T) {
	cm := NewManager(
		testCache, testServerCerts,
		serverId, "fakeServerAddr",
		errorCh, certsFixture.GetTestBaseSVID(), baseSVIDKey, regEntries, testLogger)
	stop := make(chan struct{})
	go cm.UpdateCache(stop)
	//time.Sleep(1*time.Second)
	//cm.CacheEntryCh = make(chan cache.CacheEntry)
	//cm.CacheEntryCh<-testCacheEntry
	//assert.NotEmpty(t,cm.managedCache.Entry([]*common.Selector{
	//	&common.Selector{Type: "unix", Value: "uid:111"},
	//}))
	stop <- struct{}{}
}
