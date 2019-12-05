package attestor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_workload "github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
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
		Log:     log,
		Metrics: telemetry.Blackhole{},
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

func (s *WorkloadAttestorTestSuite) TestAttestWorkloadMetrics() {
	// Add only one attestor
	catalog := fakeagentcatalog.New()
	catalog.SetWorkloadAttestors(
		fakeagentcatalog.WorkloadAttestor("fake1", s.attestor1),
	)
	// Use fake metrics
	metrics := fakemetrics.New()

	s.attestor.c.Metrics = metrics
	s.attestor.c.Catalog = catalog

	// Create context with life limit
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	// Without the security header
	selectors1 := []*common.Selector{{Type: "foo", Value: "bar"}}

	// attestor1 has selectors, but not attestor2
	s.attestor1.SetSelectors(2, selectors1)

	// Expect selectors from both attestors
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
	selectors = s.attestor.Attest(ctx, 1)
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
