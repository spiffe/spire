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
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/api/workload"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/mock/agent/manager"
	"github.com/spiffe/spire/test/mock/agent/manager/cache"
	"github.com/spiffe/spire/test/mock/proto/agent/workloadattestor"
	"github.com/spiffe/spire/test/mock/proto/api/workload"
	"github.com/spiffe/spire/test/util"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

type HandlerTestSuite struct {
	suite.Suite

	h    *Handler
	ctrl *gomock.Controller

	attestor *mock_workloadattestor.MockWorkloadAttestor
	cache    *mock_cache.MockCache
	manager  *mock_manager.MockManager
	stream   *mock_workload.MockSpiffeWorkloadAPI_FetchX509SVIDServer
}

func (s *HandlerTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(s.T())
	log, _ := test.NewNullLogger()

	s.attestor = mock_workloadattestor.NewMockWorkloadAttestor(mockCtrl)
	s.cache = mock_cache.NewMockCache(mockCtrl)
	s.manager = mock_manager.NewMockManager(mockCtrl)
	s.stream = mock_workload.NewMockSpiffeWorkloadAPI_FetchX509SVIDServer(mockCtrl)

	catalog := fakeagentcatalog.New()
	catalog.SetWorkloadAttestors(s.attestor)

	h := &Handler{
		Manager: s.manager,
		Catalog: catalog,
		L:       log,
		T:       telemetry.Blackhole{},
	}

	s.h = h
	s.ctrl = mockCtrl
}

func TestWorkloadServer(t *testing.T) {
	suite.Run(t, new(HandlerTestSuite))
}

func (s *HandlerTestSuite) TearDownTest() {
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
	s.stream.EXPECT().Context().Return(ctx)
	err = s.h.FetchX509SVID(nil, s.stream)
	s.Assert().Error(err)

	p := &peer.Peer{
		AuthInfo: auth.CallerInfo{
			PID: 1,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	ctx = peer.NewContext(ctx, p)
	ctx = metadata.NewIncomingContext(ctx, header)
	selectors := []*common.Selector{{Type: "foo", Value: "bar"}}
	subscriber := mock_cache.NewMockSubscriber(s.ctrl)
	subscription := make(chan *cache.WorkloadUpdate)
	subscriber.EXPECT().Updates().Return(subscription).AnyTimes()
	subscriber.EXPECT().Finish()
	result := make(chan error)
	s.stream.EXPECT().Context().Return(ctx).AnyTimes()
	s.attestor.EXPECT().Attest(gomock.Any(), &workloadattestor.AttestRequest{Pid: int32(1)}).Return(&workloadattestor.AttestResponse{Selectors: selectors}, nil)
	s.manager.EXPECT().SubscribeToCacheChanges(cache.Selectors{selectors[0]}).Return(subscriber)
	s.stream.EXPECT().Send(gomock.Any())
	go func() { result <- s.h.FetchX509SVID(nil, s.stream) }()

	// Make sure it's still running...
	select {
	case err := <-result:
		s.T().Errorf("hander exited immediately: %v", err)
	case <-time.NewTimer(1 * time.Millisecond).C:
	}

	select {
	case <-time.NewTimer(1 * time.Second).C:
		s.T().Error("timeout sending update to workload handler")
	case subscription <- s.workloadUpdate():
	}

	cancel()
	select {
	case err := <-result:
		s.Assert().NoError(err)
	case <-time.NewTimer(1 * time.Second).C:
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
		SpiffeId:      "spiffe://example.org/foo",
		X509Svid:      update.Entries[0].SVID.Raw,
		X509SvidKey:   keyData,
		Bundle:        update.Bundle[0].Raw,
		FederatesWith: []string{"spiffe://otherdomain.test"},
	}
	apiMsg := &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{svidMsg},
		FederatedBundles: map[string][]byte{
			"spiffe://otherdomain.test": update.Bundle[0].Raw,
		},
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

func (s *HandlerTestSuite) workloadUpdate() *cache.WorkloadUpdate {
	svid, key, err := util.LoadSVIDFixture()
	s.Require().NoError(err)
	ca, _, err := util.LoadCAFixture()
	s.Require().NoError(err)

	entry := cache.Entry{
		SVID:       svid,
		PrivateKey: key,
		RegistrationEntry: &common.RegistrationEntry{
			SpiffeId:      "spiffe://example.org/foo",
			FederatesWith: []string{"spiffe://otherdomain.test"},
		},
	}
	update := &cache.WorkloadUpdate{
		Entries: []*cache.Entry{&entry},
		Bundle:  []*x509.Certificate{ca},
		FederatedBundles: map[string][]*x509.Certificate{
			"spiffe://otherdomain.test": {ca},
		},
	}

	return update
}
