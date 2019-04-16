package attestor

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakeworkloadattestor"
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

	attestor  *attestor
	attestor1 *fakeworkloadattestor.WorkloadAttestor
	attestor2 *fakeworkloadattestor.WorkloadAttestor
}

func (s *WorkloadAttestorTestSuite) SetupTest() {
	s.attestor1 = fakeworkloadattestor.New()
	s.attestor2 = fakeworkloadattestor.New()

	log, _ := test.NewNullLogger()

	catalog := fakeagentcatalog.New()
	catalog.SetWorkloadAttestors(
		fakeagentcatalog.WorkloadAttestor("fake1", s.attestor1),
		fakeagentcatalog.WorkloadAttestor("fake2", s.attestor2),
	)

	s.attestor = newAttestor(&Config{
		Catalog: catalog,
		L:       log,
		M:       telemetry.Blackhole{},
	})
}

func (s *WorkloadAttestorTestSuite) TestAttestWorkload() {
	selectors1 := []*common.Selector{{Type: "foo", Value: "bar"}}
	selectors2 := []*common.Selector{{Type: "bat", Value: "baz"}}
	combined := append(selectors1, selectors2...)
	util.SortSelectors(combined)

	// both attestors succeed but with no selectors
	s.attestor1.SetSelectors(1, nil)
	s.attestor2.SetSelectors(1, nil)
	selectors := s.attestor.Attest(ctx, 1)
	s.Empty(selectors)

	// attestor1 has selectors, but not attestor2
	s.attestor1.SetSelectors(2, selectors1)
	s.attestor2.SetSelectors(2, nil)
	selectors = s.attestor.Attest(ctx, 2)
	s.Equal(selectors1, selectors)

	// attestor2 has selectors, attestor1 fails
	s.attestor2.SetSelectors(3, selectors2)
	selectors = s.attestor.Attest(ctx, 3)
	s.Equal(selectors2, selectors)

	// both have selectors
	s.attestor1.SetSelectors(4, selectors1)
	s.attestor2.SetSelectors(4, selectors2)
	selectors = s.attestor.Attest(ctx, 4)
	util.SortSelectors(selectors)
	s.Equal(combined, selectors)
}
