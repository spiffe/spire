package workload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/agent/catalog"
	"github.com/spiffe/spire/test/mock/agent/manager"
	"github.com/spiffe/spire/test/mock/agent/manager/cache"
	"github.com/spiffe/spire/test/mock/proto/agent/workloadattestor"
	"github.com/stretchr/testify/suite"
)

var (
	selector1 = &selector.Selector{Type: "foo", Value: "bar"}
	selector2 = &selector.Selector{Type: "bar", Value: "bat"}
	selector3 = &selector.Selector{Type: "bat", Value: "baz"}
	selector4 = &selector.Selector{Type: "baz", Value: "quz"}
)

type HandlerTestSuite struct {
	suite.Suite

	h *Handler

	attestor1 *mock_workloadattestor.MockWorkloadAttestor
	attestor2 *mock_workloadattestor.MockWorkloadAttestor
	cache     *mock_cache.MockCache
	catalog   *mock_catalog.MockCatalog
	manager   *mock_manager.MockManager

	// Logrus test hook for asserting
	// log messages, if desired
	logHook *test.Hook

	t    *testing.T
	ctrl *gomock.Controller
}

func (s *HandlerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.t)
	log, logHook := test.NewNullLogger()
	maxTTL := 12 * time.Hour
	minTTL := 5 * time.Second

	s.attestor1 = mock_workloadattestor.NewMockWorkloadAttestor(mockCtrl)
	s.attestor2 = mock_workloadattestor.NewMockWorkloadAttestor(mockCtrl)
	s.cache = mock_cache.NewMockCache(mockCtrl)
	s.catalog = mock_catalog.NewMockCatalog(mockCtrl)
	s.manager = mock_manager.NewMockManager(mockCtrl)

	ws := &Handler{
		CacheMgr: s.manager,
		Catalog:  s.catalog,
		L:        log,
		Bundle:   []*x509.Certificate{},
		MaxTTL:   maxTTL,
		MinTTL:   minTTL,
	}

	s.h = ws
	s.logHook = logHook
	s.ctrl = mockCtrl
}

func (s *HandlerTestSuite) TeardownTest() {
	s.ctrl.Finish()
}

func (s *HandlerTestSuite) TestAttestCaller() {
	var testPID int32 = 1000
	plugins := []workloadattestor.WorkloadAttestor{s.attestor1, s.attestor2}
	pRequest := &workloadattestor.AttestRequest{Pid: testPID}
	pRes1 := &workloadattestor.AttestResponse{Selectors: selector.NewSet(selector1).Raw()}
	pRes2 := &workloadattestor.AttestResponse{Selectors: selector.NewSet(selector2, selector3).Raw()}

	s.catalog.EXPECT().WorkloadAttestors().Return(plugins)
	s.attestor1.EXPECT().Attest(pRequest).Return(pRes1, nil)
	s.attestor2.EXPECT().Attest(pRequest).Return(pRes2, nil)

	selectors, err := s.h.attestCaller(testPID)
	if s.Assert().Nil(err) {
		expected := selector.NewSet(selector1, selector2, selector3)
		got := selector.NewSetFromRaw(selectors)
		s.Assert().True(expected.Equal(got))
	}
}

func (s *HandlerTestSuite) TestAttestCallerError() {
	var testPID int32 = 1000
	pluginName := "WorkloadAttestor"
	plugins := []workloadattestor.WorkloadAttestor{s.attestor1, s.attestor2}
	pRequest := &workloadattestor.AttestRequest{Pid: testPID}
	pRes1 := &workloadattestor.AttestResponse{Selectors: selector.NewSet(selector1).Raw()}
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

	selectors, errs := s.h.attestCaller(testPID)
	s.Assert().Nil(errs)

	expected := selector.NewSet(selector1)
	got := selector.NewSetFromRaw(selectors)
	s.Assert().True(expected.Equal(got))
}

func (s *HandlerTestSuite) TestComposeResponse() {
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
	cacheEntry := cache.Entry{
		RegistrationEntry: registrationEntry,
		SVID:              svid,
		PrivateKey:        key,
		Bundles:           make(map[string][]byte),
	}

	entries := []cache.Entry{cacheEntry}
	resp, err := s.h.composeResponse(entries)
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

func (s *HandlerTestSuite) TestCalculateTTL() {
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
		res := s.h.calculateTTL(certs)
		s.Assert().Equal(c.out, int(res.Seconds()))
	}
}

func generateCacheEntry(spiffeID, parentID string, selectors selector.Set) (cache.Entry, error) {
	registrationEntry := &common.RegistrationEntry{
		Selectors:   selectors.Raw(),
		ParentId:    parentID,
		SpiffeId:    spiffeID,
		Ttl:         3600,
		FbSpiffeIds: []string{},
	}

	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		return cache.Entry{}, err
	}

	svid := &x509.Certificate{
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(3600 * time.Second),
	}
	cacheEntry := cache.Entry{
		RegistrationEntry: registrationEntry,
		SVID:              svid,
		PrivateKey:        key,
		Bundles:           make(map[string][]byte),
	}

	return cacheEntry, nil
}

func TestWorkloadServer(t *testing.T) {
	suite.Run(t, new(HandlerTestSuite))
}
