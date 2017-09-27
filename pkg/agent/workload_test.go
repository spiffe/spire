package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sort"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/suite"

	"github.com/spiffe/spire/pkg/agent/cache"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/agent/cache"
	"github.com/spiffe/spire/test/mock/agent/catalog"
	"github.com/spiffe/spire/test/mock/agent/workloadattestor"
)

var (
	selector1 *selector.Selector = &selector.Selector{Type: "foo", Value: "bar"}
	selector2 *selector.Selector = &selector.Selector{Type: "bar", Value: "bat"}
	selector3 *selector.Selector = &selector.Selector{Type: "bat", Value: "baz"}
	selector4 *selector.Selector = &selector.Selector{Type: "baz", Value: "quz"}
)

type WorkloadServerTestSuite struct {
	suite.Suite

	w *workloadServer

	attestor1 *mock_workloadattestor.MockWorkloadAttestor
	attestor2 *mock_workloadattestor.MockWorkloadAttestor
	cache     *mock_cache.MockCache
	catalog   *mock_catalog.MockCatalog

	// Logrus test hook for asserting
	// log messages, if desired
	logHook *test.Hook

	t    *testing.T
	ctrl *gomock.Controller
}

func (s *WorkloadServerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.t)
	log, logHook := test.NewNullLogger()
	ttl := 12 * time.Hour

	s.attestor1 = mock_workloadattestor.NewMockWorkloadAttestor(mockCtrl)
	s.attestor2 = mock_workloadattestor.NewMockWorkloadAttestor(mockCtrl)
	s.cache = mock_cache.NewMockCache(mockCtrl)
	s.catalog = mock_catalog.NewMockCatalog(mockCtrl)

	ws := &workloadServer{
		cache:   s.cache,
		catalog: s.catalog,
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

func (s *WorkloadServerTestSuite) TestAttestCaller() {
	var testPID int32 = 1000
	plugins := []workloadattestor.WorkloadAttestor{s.attestor1, s.attestor2}
	pRequest := &workloadattestor.AttestRequest{Pid: testPID}
	pRes1 := &workloadattestor.AttestResponse{Selectors: selector.Set{selector1}.Raw()}
	pRes2 := &workloadattestor.AttestResponse{Selectors: selector.Set{selector2, selector3}.Raw()}

	s.catalog.EXPECT().WorkloadAttestors().Return(plugins, nil)
	s.attestor1.EXPECT().Attest(pRequest).Return(pRes1, nil)
	s.attestor2.EXPECT().Attest(pRequest).Return(pRes2, nil)

	selectors, err := s.w.attestCaller(testPID)
	if s.Assert().Nil(err) {
		expected := selector.Set{selector1, selector2, selector3}
		got := selector.NewSet(selectors)
		sort.Sort(expected)
		sort.Sort(got)
		s.Assert().Equal(expected, got)
	}
}

func (s *WorkloadServerTestSuite) TestFindEntries() {
	set := selector.Set{selector2}
	entry1, err := generateCacheEntry("spiffe://example.org/bat", "spiffe://example.org/baz", set)
	s.Assert().Nil(err)

	s.cache.EXPECT().Entry(set.Raw()).Return([]cache.CacheEntry{entry1})
	s.cache.EXPECT().Entry(gomock.Any()).Return([]cache.CacheEntry{}).AnyTimes()

	res := s.w.findEntries(selector.Set{selector1, selector2})
	s.Assert().Equal([]cache.CacheEntry{entry1}, res)
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

	expiry := time.Now().Add(3600 * time.Second)
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
