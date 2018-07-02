package attestor

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/agent/catalog"
	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/selector"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/api/node"
	"github.com/spiffe/spire/proto/common"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/mock/proto/agent/workloadattestor"
	"github.com/stretchr/testify/suite"
)

var (
	ctx = context.Background()
)

func TestWorkloadAttestor(t *testing.T) {
	suite.Run(t, new(WorkloadAttestorTestSuite))
}

type WorkloadAttestorTestSuite struct {
	suite.Suite

	ctrl *gomock.Controller

	attestor    *attestor
	expectation *node.X509SVIDUpdate
	attestor1   *mock_workloadattestor.MockWorkloadAttestor
	attestor2   *mock_workloadattestor.MockWorkloadAttestor
}

func (s *WorkloadAttestorTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())

	s.attestor1 = mock_workloadattestor.NewMockWorkloadAttestor(s.ctrl)
	s.attestor2 = mock_workloadattestor.NewMockWorkloadAttestor(s.ctrl)

	log, _ := test.NewNullLogger()

	catalog := fakeagentcatalog.New()
	catalog.SetWorkloadAttestors(s.attestor1, s.attestor2)

	s.attestor = newAttestor(&Config{
		Catalog: catalog,
		L:       log,
		T:       telemetry.Blackhole{},
	})
}

func (s *WorkloadAttestorTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

func (s *WorkloadAttestorTestSuite) TestAttestWorkload() {
	sel1 := []*common.Selector{{Type: "foo", Value: "bar"}}
	sel2 := []*common.Selector{{Type: "bat", Value: "baz"}}
	s.attestor1.EXPECT().Attest(gomock.Any(), gomock.Any()).Return(&workloadattestor.AttestResponse{Selectors: sel1}, nil)
	s.attestor2.EXPECT().Attest(gomock.Any(), gomock.Any()).Return(&workloadattestor.AttestResponse{Selectors: sel2}, nil)

	// Use selector package to work around sort ordering
	expected := selector.NewSetFromRaw([]*common.Selector{sel1[0], sel2[0]})
	result := s.attestor.Attest(ctx, 1)
	s.Assert().Equal(expected, selector.NewSetFromRaw(result))

	s.attestor1.EXPECT().Attest(gomock.Any(), gomock.Any()).Return(nil, errors.New("i'm an error"))
	s.attestor2.EXPECT().Attest(gomock.Any(), gomock.Any()).Return(&workloadattestor.AttestResponse{Selectors: sel2}, nil)

	s.Assert().Equal(sel2, s.attestor.Attest(ctx, 1))
}

func (s *WorkloadAttestorTestSuite) TestInvokeAttestor() {
	req := &workloadattestor.AttestRequest{Pid: 1}
	sel := []*common.Selector{{Type: "foo", Value: "bar"}}
	resp := &workloadattestor.AttestResponse{Selectors: sel}
	s.attestor1.EXPECT().Attest(gomock.Any(), req).Return(resp, nil)

	managedAttestor := catalog.NewManagedWorkloadAttestor(s.attestor1, common_catalog.PluginConfig{
		PluginName: "foo",
	})

	result, err := s.attestor.invokeAttestor(ctx, managedAttestor, 1)
	s.Require().NoError(err)
	s.Require().Equal(sel, result)

	s.attestor1.EXPECT().Attest(gomock.Any(), req).Return(nil, errors.New("i'm an error"))
	result, err = s.attestor.invokeAttestor(ctx, managedAttestor, 1)
	s.Require().EqualError(err, `workload attestor "foo" failed: i'm an error`)
	s.Require().Nil(result)
}
