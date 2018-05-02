package workload

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/suite"

	"github.com/spiffe/spire/pkg/agent/auth"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/agent/catalog"
	"github.com/spiffe/spire/test/mock/agent/manager"
	"github.com/spiffe/spire/test/mock/agent/manager/cache"
	"github.com/spiffe/spire/test/mock/proto/agent/workloadattestor"
	"github.com/spiffe/spire/test/mock/proto/api/workload"
	"github.com/spiffe/spire/test/util"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	cc "github.com/spiffe/spire/pkg/common/catalog"
)

type HandlerTestSuite struct {
	suite.Suite

	h    *Handler
	ctrl *gomock.Controller

	attestor1 *mock_workloadattestor.MockWorkloadAttestor
	attestor2 *mock_workloadattestor.MockWorkloadAttestor
	cache     *mock_cache.MockCache
	catalog   *mock_catalog.MockCatalog
	manager   *mock_manager.MockManager
	stream    *mock_workload.MockSpiffeWorkloadAPI_FetchX509SVIDServer
}

func (s *HandlerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.T())
	log, _ := test.NewNullLogger()

	s.attestor1 = mock_workloadattestor.NewMockWorkloadAttestor(mockCtrl)
	s.attestor2 = mock_workloadattestor.NewMockWorkloadAttestor(mockCtrl)
	s.cache = mock_cache.NewMockCache(mockCtrl)
	s.catalog = mock_catalog.NewMockCatalog(mockCtrl)
	s.manager = mock_manager.NewMockManager(mockCtrl)
	s.stream = mock_workload.NewMockSpiffeWorkloadAPI_FetchX509SVIDServer(mockCtrl)

	h := &Handler{
		Manager: s.manager,
		Catalog: s.catalog,
		L:       log,
		T:       telemetry.Blackhole{},
	}

	s.h = h
	s.ctrl = mockCtrl
}

func TestWorkloadServer(t *testing.T) {
	suite.Run(t, new(HandlerTestSuite))
}

func (s *HandlerTestSuite) TeardownTest() {
	s.ctrl.Finish()
}

func (s *HandlerTestSuite) TestFetchX509SVID() {
	// Without the security header
	s.stream.EXPECT().Context().Return(context.Background())
	err := s.h.FetchX509SVID(nil, s.stream)
	s.Assert().Error(err)

	// Without PID data
	header := metadata.Pairs("workload.spiffe.io", "true")
	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, header)
	s.stream.EXPECT().Context().Return(ctx).Times(2)
	err = s.h.FetchX509SVID(nil, s.stream)
	s.Assert().Error(err)

	p := &peer.Peer{
		AuthInfo: auth.CallerInfo{
			PID: 1,
		},
	}
	ctx = peer.NewContext(context.Background(), p)
	ctx = metadata.NewIncomingContext(ctx, header)
	ctx, cancel := context.WithCancel(ctx)
	selectors := []*common.Selector{{Type: "foo", Value: "bar"}}
	subscriber := mock_cache.NewMockSubscriber(s.ctrl)
	subscription := make(chan *cache.WorkloadUpdate)
	subscriber.EXPECT().Updates().Return(subscription).AnyTimes()
	subscriber.EXPECT().Finish()
	result := make(chan error)
	s.stream.EXPECT().Context().Return(ctx).Times(4)
	s.catalog.EXPECT().Find(gomock.Any()).AnyTimes()
	s.catalog.EXPECT().WorkloadAttestors().Return([]workloadattestor.WorkloadAttestor{s.attestor1})
	s.attestor1.EXPECT().Attest(&workloadattestor.AttestRequest{Pid: int32(1)}).Return(&workloadattestor.AttestResponse{selectors}, nil)
	s.manager.EXPECT().Subscribe(cache.Selectors{selectors[0]}).Return(subscriber)
	s.stream.EXPECT().Send(gomock.Any())
	go func() { result <- s.h.FetchX509SVID(nil, s.stream) }()

	// Make sure it's still running...
	select {
	case err := <-result:
		s.T().Errorf("hander exited immediately: %v", err)
	case <-time.NewTicker(1 * time.Millisecond).C:
	}

	select {
	case <-time.NewTicker(1 * time.Second).C:
		s.T().Error("timeout sending update to workload handler")
	case subscription <- s.workloadUpdate():
	}

	cancel()
	select {
	case err := <-result:
		s.Assert().NoError(err)
	case <-time.NewTicker(1 * time.Second).C:
		s.T().Error("workload handler hung, shutdown timer exceeded")
	}
}

func (s *HandlerTestSuite) TestSendResponse() {
	emptyUpdate := new(cache.WorkloadUpdate)
	s.stream.EXPECT().Send(gomock.Any()).Times(0)
	err := s.h.sendResponse(emptyUpdate, s.stream)
	s.Assert().Error(err)

	resp, err := s.h.composeResponse(s.workloadUpdate())
	s.Require().NoError(err)
	s.stream.EXPECT().Send(resp)
	err = s.h.sendResponse(s.workloadUpdate(), s.stream)
	s.Assert().NoError(err)
}

func (s *HandlerTestSuite) TestComposeResponse() {
	update := s.workloadUpdate()
	keyData, err := x509.MarshalPKCS8PrivateKey(update.Entries[0].PrivateKey)
	s.Require().NoError(err)

	svidMsg := &workload.X509SVID{
		SpiffeId:    "spiffe://example.org/foo",
		X509Svid:    update.Entries[0].SVID.Raw,
		X509SvidKey: keyData,
		Bundle:      update.Bundle[0].Raw,
	}
	apiMsg := &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{svidMsg},
	}

	resp, err := s.h.composeResponse(s.workloadUpdate())
	s.Assert().NoError(err)
	s.Assert().Equal(apiMsg, resp)
}

func (s *HandlerTestSuite) TestCallerPID() {
	p := &peer.Peer{
		AuthInfo: auth.CallerInfo{
			PID: 1,
		},
	}
	ctx := peer.NewContext(context.Background(), p)

	pid, err := s.h.callerPID(ctx)
	s.Assert().NoError(err)
	s.Assert().Equal(int32(1), pid)

	// Couldn't get PID via socket opt
	p = &peer.Peer{
		AuthInfo: auth.CallerInfo{
			PID: 0,
			Err: errors.New("i'm an error"),
		},
	}
	ctx = peer.NewContext(context.Background(), p)
	_, err = s.h.callerPID(ctx)
	s.Assert().Error(err)

	// Implementation error - custom auth creds not in use
	p.AuthInfo = nil
	ctx = peer.NewContext(context.Background(), p)
	_, err = s.h.callerPID(ctx)
	s.Assert().Error(err)
}

func (s *HandlerTestSuite) TestAttest() {
	attestors := []workloadattestor.WorkloadAttestor{
		s.attestor1,
		s.attestor2,
	}
	s.catalog.EXPECT().WorkloadAttestors().Return(attestors)
	s.catalog.EXPECT().Find(gomock.Any()).AnyTimes()

	sel1 := []*common.Selector{{Type: "foo", Value: "bar"}}
	sel2 := []*common.Selector{{Type: "bat", Value: "baz"}}
	s.attestor1.EXPECT().Attest(gomock.Any()).Return(&workloadattestor.AttestResponse{sel1}, nil)
	s.attestor2.EXPECT().Attest(gomock.Any()).Return(&workloadattestor.AttestResponse{sel2}, nil)

	// Use selector package to work around sort ordering
	expected := selector.NewSetFromRaw([]*common.Selector{sel1[0], sel2[0]})
	result := s.h.attest(1)
	s.Assert().Equal(expected, selector.NewSetFromRaw(result))

	s.catalog.EXPECT().WorkloadAttestors().Return(attestors)
	s.attestor1.EXPECT().Attest(gomock.Any()).Return(nil, errors.New("i'm an error"))
	s.attestor2.EXPECT().Attest(gomock.Any()).Return(&workloadattestor.AttestResponse{sel2}, nil)

	s.Assert().Equal(sel2, s.h.attest(1))
}

func (s *HandlerTestSuite) TestInvokeAttestor() {
	sChan := make(chan []*common.Selector)
	errChan := make(chan error)

	req := &workloadattestor.AttestRequest{Pid: 1}
	sel := []*common.Selector{{Type: "foo", Value: "bar"}}
	resp := &workloadattestor.AttestResponse{Selectors: sel}
	s.attestor1.EXPECT().Attest(req).Return(resp, nil)
	s.catalog.EXPECT().Find(gomock.Any()).AnyTimes()

	timeout := time.NewTicker(5 * time.Millisecond)
	go s.h.invokeAttestor(s.attestor1, 1, sChan, errChan)
	select {
	case result := <-sChan:
		s.Assert().Equal(sel, result)
	case err := <-errChan:
		s.T().Errorf("Unexpected failure trying to invoke workload attestor: %v", err)
	case <-timeout.C:
		s.T().Error("Workload invocation has hung")
	}

	findResp := &cc.ManagedPlugin{
		Plugin: s.attestor1,
		Config: cc.PluginConfig{
			PluginName: "foo",
		},
	}
	s.catalog.EXPECT().Find(s.attestor1).Return(findResp)
	s.attestor1.EXPECT().Attest(req).Return(nil, errors.New("i'm an error"))
	go s.h.invokeAttestor(s.attestor1, 1, sChan, errChan)
	select {
	case sel := <-sChan:
		s.T().Errorf("Wanted error, got selectors: %v", sel)
	case <-timeout.C:
		s.T().Error("Workload invocation has hung")
	case <-errChan:
	}
}

func (s *HandlerTestSuite) TestAttestorName() {
	resp := &cc.ManagedPlugin{
		Plugin: s.attestor1,
		Config: cc.PluginConfig{
			PluginName: "foo",
		},
	}
	s.catalog.EXPECT().Find(s.attestor1).Return(resp)
	s.Assert().Equal("foo", s.h.attestorName(s.attestor1))

	s.catalog.EXPECT().Find(s.attestor1).Return(nil)
	s.Assert().Equal("unknown", s.h.attestorName(s.attestor1))
}

func (s *HandlerTestSuite) workloadUpdate() *cache.WorkloadUpdate {
	svid, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)
	ca, _, err := util.LoadCAFixture()
	s.Require().NoError(err)

	entry := cache.Entry{
		SVID:       svid,
		PrivateKey: key,
		RegistrationEntry: &common.RegistrationEntry{
			SpiffeId: "spiffe://example.org/foo",
		},
	}
	update := &cache.WorkloadUpdate{
		Entries: []*cache.Entry{&entry},
		Bundle:  []*x509.Certificate{ca},
	}

	return update
}
