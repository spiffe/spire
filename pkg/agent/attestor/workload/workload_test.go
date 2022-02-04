package attestor

import (
	"context"
	"errors"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_workload "github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/fakes/fakeworkloadattestor"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/suite"
)

var (
	ctx = context.Background()

	selectors1 = []*common.Selector{{Type: "fake1", Value: "bar"}}
	selectors2 = []*common.Selector{{Type: "fake2", Value: "baz"}}

	attestor1Pids = map[int32][]string{
		1: nil,
		2: []string{"bar"},
		// 3: attestor1 cannot attest process 3
		4: []string{"bar"},
	}
	attestor2Pids = map[int32][]string{
		1: nil,
		2: nil,
		3: []string{"baz"},
		4: []string{"baz"},
	}
)

func TestWorkloadAttestor(t *testing.T) {
	suite.Run(t, new(WorkloadAttestorTestSuite))
}

type WorkloadAttestorTestSuite struct {
	suite.Suite

	attestor *attestor
	catalog  *fakeagentcatalog.Catalog
}

func (s *WorkloadAttestorTestSuite) SetupTest() {
	log, _ := test.NewNullLogger()

	s.catalog = fakeagentcatalog.New()
	s.attestor = newAttestor(&Config{
		Catalog: s.catalog,
		Log:     log,
		Metrics: telemetry.Blackhole{},
	})
}

func (s *WorkloadAttestorTestSuite) TestAttestWorkload() {
	s.catalog.SetWorkloadAttestors(
		fakeworkloadattestor.New(s.T(), "fake1", attestor1Pids),
		fakeworkloadattestor.New(s.T(), "fake2", attestor2Pids),
	)

	// both attestors succeed but with no selectors
	selectors := s.attestor.Attest(ctx, 1)
	s.Empty(selectors)

	// attestor1 has selectors, but not attestor2
	selectors = s.attestor.Attest(ctx, 2)
	spiretest.AssertProtoListEqual(s.T(), selectors1, selectors)

	// attestor2 has selectors, attestor1 fails
	selectors = s.attestor.Attest(ctx, 3)
	spiretest.AssertProtoListEqual(s.T(), selectors2, selectors)

	// both have selectors
	selectors = s.attestor.Attest(ctx, 4)
	util.SortSelectors(selectors)
	combined := make([]*common.Selector, 0, len(selectors1)+len(selectors2))
	combined = append(combined, selectors1...)
	combined = append(combined, selectors2...)
	util.SortSelectors(combined)
	spiretest.AssertProtoListEqual(s.T(), combined, selectors)
}

func (s *WorkloadAttestorTestSuite) TestAttestWorkloadMetrics() {
	// Add only one attestor
	s.catalog.SetWorkloadAttestors(
		fakeworkloadattestor.New(s.T(), "fake1", attestor1Pids),
	)

	// Use fake metrics
	metrics := fakemetrics.New()
	s.attestor.c.Metrics = metrics

	selectors := s.attestor.Attest(ctx, 2)

	// Create expected metrics
	expected := fakemetrics.New()
	attestorCounter := telemetry_workload.StartAttestorCall(expected, "fake1")
	attestorCounter.Done(nil)
	telemetry_workload.AddDiscoveredSelectorsSample(expected, float32(len(selectors)))
	attestationCounter := telemetry_workload.StartAttestationCall(expected)
	attestationCounter.Done(nil)

	s.Require().Equal(expected.AllMetrics(), metrics.AllMetrics())

	// Clean metrics to try it again
	metrics = fakemetrics.New()
	s.attestor.c.Metrics = metrics

	// No selectors expected
	selectors = s.attestor.Attest(ctx, 3)
	s.Empty(selectors)

	// Create expected metrics with error key
	expected = fakemetrics.New()
	err := errors.New("some error")
	attestorCounter = telemetry_workload.StartAttestorCall(expected, "fake1")
	attestorCounter.Done(&err)
	telemetry_workload.AddDiscoveredSelectorsSample(expected, float32(0))
	attestationCounter = telemetry_workload.StartAttestationCall(expected)
	attestationCounter.Done(nil)

	s.Require().Equal(expected.AllMetrics(), metrics.AllMetrics())
}
