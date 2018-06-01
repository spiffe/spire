package attestor

import (
	"context"
	"errors"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	cc "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/mock/agent/catalog"
	"github.com/spiffe/spire/test/mock/proto/agent/workloadattestor"
	"github.com/stretchr/testify/suite"
)

var (
	ctx = context.Background()
)

type WorkloadAttestorTestSuite struct {
	suite.Suite

	ctrl *gomock.Controller

	catalog     *mock_catalog.MockCatalog
	attestor    *attestor
	expectation *node.SvidUpdate
	attestor1   *mock_workloadattestor.MockWorkloadAttestor
	attestor2   *mock_workloadattestor.MockWorkloadAttestor
}

func (s *WorkloadAttestorTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())

	s.attestor1 = mock_workloadattestor.NewMockWorkloadAttestor(s.ctrl)
	s.attestor2 = mock_workloadattestor.NewMockWorkloadAttestor(s.ctrl)

	log, _ := test.NewNullLogger()

	s.attestor.c = &Config{
		Catalog: s.catalog,
		L:       log,
		T:       telemetry.Blackhole{},
	}
}

func (s *WorkloadAttestorTestSuite) TeardownTest() {
	s.ctrl.Finish()
}

func (s *WorkloadAttestorTestSuite) TestAttestWorkload() {
	attestors := []workloadattestor.WorkloadAttestor{
		s.attestor1,
		s.attestor2,
	}
	s.catalog.EXPECT().WorkloadAttestors().Return(attestors)
	s.catalog.EXPECT().Find(gomock.Any()).AnyTimes()

	sel1 := []*common.Selector{{Type: "foo", Value: "bar"}}
	sel2 := []*common.Selector{{Type: "bat", Value: "baz"}}
	s.attestor1.EXPECT().Attest(gomock.Any(), gomock.Any()).Return(&workloadattestor.AttestResponse{Selectors: sel1}, nil)
	s.attestor2.EXPECT().Attest(gomock.Any(), gomock.Any()).Return(&workloadattestor.AttestResponse{Selectors: sel2}, nil)

	// Use selector package to work around sort ordering
	expected := selector.NewSetFromRaw([]*common.Selector{sel1[0], sel2[0]})
	result := s.attestor.Attest(ctx, 1)
	s.Assert().Equal(expected, selector.NewSetFromRaw(result))

	s.catalog.EXPECT().WorkloadAttestors().Return(attestors)
	s.attestor1.EXPECT().Attest(gomock.Any(), gomock.Any()).Return(nil, errors.New("i'm an error"))
	s.attestor2.EXPECT().Attest(gomock.Any(), gomock.Any()).Return(&workloadattestor.AttestResponse{Selectors: sel2}, nil)

	s.Assert().Equal(sel2, s.attestor.Attest(ctx, 1))
}

func (s *WorkloadAttestorTestSuite) TestInvokeAttestor() {
	sChan := make(chan []*common.Selector)
	errChan := make(chan error)

	req := &workloadattestor.AttestRequest{Pid: 1}
	sel := []*common.Selector{{Type: "foo", Value: "bar"}}
	resp := &workloadattestor.AttestResponse{Selectors: sel}
	s.attestor1.EXPECT().Attest(gomock.Any(), req).Return(resp, nil)
	s.catalog.EXPECT().Find(gomock.Any()).AnyTimes()

	timeout := time.NewTicker(5 * time.Millisecond)
	go s.attestor.invokeAttestor(ctx, s.attestor1, 1, sChan, errChan)
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
	s.attestor1.EXPECT().Attest(gomock.Any(), req).Return(nil, errors.New("i'm an error"))
	go s.attestor.invokeAttestor(ctx, s.attestor1, 1, sChan, errChan)
	select {
	case sel := <-sChan:
		s.T().Errorf("Wanted error, got selectors: %v", sel)
	case <-timeout.C:
		s.T().Error("Workload invocation has hung")
	case <-errChan:
	}
}

func (s *WorkloadAttestorTestSuite) TestAttestorName() {
	resp := &cc.ManagedPlugin{
		Plugin: s.attestor1,
		Config: cc.PluginConfig{
			PluginName: "foo",
		},
	}
	s.catalog.EXPECT().Find(s.attestor1).Return(resp)
	s.Assert().Equal("foo", s.attestor.attestorName(s.attestor1))

	s.catalog.EXPECT().Find(s.attestor1).Return(nil)
	s.Assert().Equal(unknownName, s.attestor.attestorName(s.attestor1))
}
