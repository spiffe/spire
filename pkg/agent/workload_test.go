package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/suite"

	"github.com/spiffe/spire/pkg/agent/cache"
	"github.com/spiffe/spire/pkg/api/node"
	"github.com/spiffe/spire/pkg/common"
	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/test/mock/cache"
)

var (
	selector1 *selector.Selector = &selector.Selector{Type: "foo", Value: "bar"}
	selector2 *selector.Selector = &selector.Selector{Type: "bar", Value: "bat"}
	selector3 *selector.Selector = &selector.Selector{Type: "bat", Value: "baz"}
	selector4 *selector.Selector = &selector.Selector{Type: "baz", Value: "quz"}
)

type WorkloadServerTestSuite struct {
	suite.Suite

	w     *workloadServer
	cache *mock_cache.MockCache

	// Logrus test hook for asserting
	// log messages, if desired
	logHook *test.Hook

	t    *testing.T
	ctrl *gomock.Controller
}

func (s *WorkloadServerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.t)
	catalog := sriplugin.NewMockPluginCatalogInterface(mockCtrl)
	log, logHook := test.NewNullLogger()
	ttl := time.Duration(12) * time.Hour

	s.cache = mock_cache.NewMockCache(mockCtrl)
	ws := &workloadServer{
		cache:   s.cache,
		catalog: catalog,
		l:       log,
		bundle:  []byte{},
		maxTTL:  ttl,
	}

	s.w = ws
	s.logHook = logHook
	s.ctrl = mockCtrl
}

func (s *WorkloadServerTestSuite) TeardownTest() {
	s.ctrl.Finish()
}

func (s *WorkloadServerTestSuite) TestComposeResponse() {
	sel := &common.Selector{Type: "foo", Value: "bar"}
	registrationEntry := &common.RegistrationEntry{
		Selectors:   []*common.Selector{sel},
		ParentId:    "spiffe://example.org/bat",
		SpiffeId:    "spiffe://example.org/baz",
		Ttl:         3600,
		FbSpiffeIds: []string{},
	}

	svid := &node.Svid{
		SvidCert: []byte{},
		Ttl:      1800,
	}

	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	s.Assert().Nil(err)

	expiry := time.Now().Add(time.Duration(3600) * time.Second)
	cacheEntry := cache.CacheEntry{
		RegistrationEntry: registrationEntry,
		SVID:              svid,
		PrivateKey:        key,
		Bundles:           make(map[string][]byte),
		Expiry:            expiry,
	}

	entries := []cache.CacheEntry{cacheEntry}
	resp, err := s.w.composeResponse(entries)
	s.Assert().Nil(err)

	if s.Assert().NotNil(resp) {
		s.Assert().True(resp.Ttl <= 1800)
		s.Assert().NotEqual(0, resp.Ttl)

		if s.Assert().NotNil(resp.Bundles[0]) {
			entry := resp.Bundles[0]
			s.Assert().Equal("spiffe://example.org/baz", entry.SpiffeId)
		}
	}
}

func generateCacheEntry(spiffeID, parentID string, selectors selector.Set) (cache.CacheEntry, error) {
	registrationEntry := &common.RegistrationEntry{
		Selectors:   selectors.Raw(),
		ParentId:    parentID,
		SpiffeId:    spiffeID,
		Ttl:         3600,
		FbSpiffeIds: []string{},
	}

	svid := &node.Svid{
		SvidCert: []byte{},
		Ttl:      1800,
	}

	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		return cache.CacheEntry{}, err
	}

	expiry := time.Now().Add(time.Duration(3600) * time.Second)
	cacheEntry := cache.CacheEntry{
		RegistrationEntry: registrationEntry,
		SVID:              svid,
		PrivateKey:        key,
		Bundles:           make(map[string][]byte),
		Expiry:            expiry,
	}

	return cacheEntry, nil
}

func TestWorkloadServer(t *testing.T) {
	suite.Run(t, new(WorkloadServerTestSuite))
}
