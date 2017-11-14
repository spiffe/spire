package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/suite"

	"github.com/spiffe/spire/pkg/agent/cache"
	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/agent/cache"
	"github.com/spiffe/spire/test/mock/agent/catalog"
	"github.com/spiffe/spire/test/mock/proto/agent/workloadattestor"
)

var (
	selector1 = &selector.Selector{Type: "foo", Value: "bar"}
	selector2 = &selector.Selector{Type: "bar", Value: "bat"}
	selector3 = &selector.Selector{Type: "bat", Value: "baz"}
	selector4 = &selector.Selector{Type: "baz", Value: "quz"}
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
	maxTTL := 12 * time.Hour
	minTTL := 5 * time.Second

	s.attestor1 = mock_workloadattestor.NewMockWorkloadAttestor(mockCtrl)
	s.attestor2 = mock_workloadattestor.NewMockWorkloadAttestor(mockCtrl)
	s.cache = mock_cache.NewMockCache(mockCtrl)
	s.catalog = mock_catalog.NewMockCatalog(mockCtrl)

	ws := &workloadServer{
		cache:   s.cache,
		catalog: s.catalog,
		l:       log,
		bundle:  []byte{},
		maxTTL:  maxTTL,
		minTTL:  minTTL,
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

	s.catalog.EXPECT().WorkloadAttestors().Return(plugins)
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

func (s *WorkloadServerTestSuite) TestAttestCallerError() {
	var testPID int32 = 1000
	pluginName := "WorkloadAttestor"
	plugins := []workloadattestor.WorkloadAttestor{s.attestor1, s.attestor2}
	pRequest := &workloadattestor.AttestRequest{Pid: testPID}
	pRes1 := &workloadattestor.AttestResponse{Selectors: selector.Set{selector1}.Raw()}
	pRes2 := &workloadattestor.AttestResponse{}
	pError2 := errors.New("failed")
	pInfo2 := &common_catalog.ManagedPlugin{
		Config: common_catalog.PluginConfig{
			PluginName: pluginName,
		},
	}

	s.catalog.EXPECT().WorkloadAttestors().Return(plugins)
	s.attestor1.EXPECT().Attest(pRequest).Return(pRes1, nil)
	s.attestor2.EXPECT().Attest(pRequest).Return(pRes2, pError2)
	s.catalog.EXPECT().Find(plugins[1].(common_catalog.Plugin)).Return(pInfo2)

	selectors, errs := s.w.attestCaller(testPID)
	s.Assert().Nil(errs)

	expected := selector.Set{selector1}
	got := selector.NewSet(selectors)
	sort.Sort(expected)
	sort.Sort(got)
	s.Assert().Equal(expected, got)
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

	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	s.Assert().Nil(err)

	svid := &x509.Certificate{
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(3600 * time.Second),
	}
	cacheEntry := cache.CacheEntry{
		RegistrationEntry: registrationEntry,
		SVID:              svid,
		PrivateKey:        key,
		Bundles:           make(map[string][]byte),
	}

	entries := []cache.CacheEntry{cacheEntry}
	resp, err := s.w.composeResponse(entries)
	s.Assert().Nil(err)

	if s.Assert().NotNil(resp) {
		s.Assert().True(resp.Ttl == 1800)
		s.Assert().NotEqual(0, resp.Ttl)

		if s.Assert().NotNil(resp.Bundles[0]) {
			entry := resp.Bundles[0]
			s.Assert().Equal("spiffe://example.org/baz", entry.SpiffeId)
		}
	}
}

func (s *WorkloadServerTestSuite) TestCalculateTTL() {
	// int approximations of Time
	var ttlCases = []struct {
		in  []int
		out int
	}{
		{[]int{1, 20}, 5}, // 5s is the configured minTTL
		{[]int{20}, 10},
	}

	// Create dummy certs with NotAfter set using input data
	for _, c := range ttlCases {
		var certs []*x509.Certificate
		for _, ttl := range c.in {
			notAfter := time.Now().Add(time.Duration(ttl) * time.Second)
			cert := &x509.Certificate{
				NotBefore: time.Now(),
				NotAfter:  notAfter,
			}
			certs = append(certs, cert)
		}

		// Assert output given cert slice
		res := s.w.calculateTTL(certs)
		s.Assert().Equal(c.out, int(res.Seconds()))
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

	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		return cache.CacheEntry{}, err
	}

	svid := &x509.Certificate{
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(3600 * time.Second),
	}
	cacheEntry := cache.CacheEntry{
		RegistrationEntry: registrationEntry,
		SVID:              svid,
		PrivateKey:        key,
		Bundles:           make(map[string][]byte),
	}

	return cacheEntry, nil
}

func TestWorkloadServer(t *testing.T) {
	suite.Run(t, new(WorkloadServerTestSuite))
}
