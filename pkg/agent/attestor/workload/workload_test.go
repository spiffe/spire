package attestor

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakeworkloadattestor"
	mock_telemetry "github.com/spiffe/spire/test/mock/common/telemetry"
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

	metrics *mock_telemetry.MockMetrics
	ctrl    *gomock.Controller
}

func (s *WorkloadAttestorTestSuite) SetupTest() {
	s.attestor1 = fakeworkloadattestor.New()
	s.attestor2 = fakeworkloadattestor.New()

	s.ctrl = gomock.NewController(s.T())
	s.metrics = mock_telemetry.NewMockMetrics(s.ctrl)

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

func (s *WorkloadAttestorTestSuite) TearDownTest() {
	s.ctrl.Finish()
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
	// Use metrics mocks
	s.attestor.c.M = s.metrics

	// Create context with life limit
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	// Without the security header
	selectors1 := []*common.Selector{{Type: "foo", Value: "bar"}}
	selectors2 := []*common.Selector{{Type: "bat", Value: "baz"}}
	combined := append(selectors1, selectors2...)
	util.SortSelectors(combined)

	// attestor1 has selectors, but not attestor2
	s.attestor1.SetSelectors(2, selectors1)
	s.attestor2.SetSelectors(2, selectors2)

	// Attestor labels
	attestorLabels := []telemetry.Label{{telemetry.Attestor, "fake1"}}
	attestorLabels2 := []telemetry.Label{{telemetry.Attestor, "fake2"}}

	// Create mocks for success scenario
	s.metrics.EXPECT().MeasureSince([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestationDuration}, gomock.Any())
	// A sample metric is created with the amount of returned selectors
	s.metrics.EXPECT().AddSample([]string{telemetry.WorkloadAPI, telemetry.DiscoveredSelectors}, float32(len(combined)))

	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency}, float32(1), attestorLabels)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency, telemetry.ElapsedTime},
		gomock.Any(), attestorLabels)

	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency}, float32(1), attestorLabels2)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency, telemetry.ElapsedTime},
		gomock.Any(), attestorLabels2)

	// Expect selectors from both attestors
	selectors := s.attestor.Attest(ctx, 2)
	util.SortSelectors(selectors)
	s.Equal(combined, selectors)

	// Create mocks for error scenario
	s.metrics.EXPECT().MeasureSince([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestationDuration}, gomock.Any())
	// A sample metric is created with empty discovered selectors
	s.metrics.EXPECT().AddSample([]string{telemetry.WorkloadAPI, telemetry.DiscoveredSelectors}, float32(0))

	// Error key is added to metric when error happens attesting a workload
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency, telemetry.Error}, float32(1), attestorLabels)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency, telemetry.Error, telemetry.ElapsedTime},
		gomock.Any(), attestorLabels)

	// Error key is added to metric when error happens attesting a workload
	s.metrics.EXPECT().IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency, telemetry.Error}, float32(1), attestorLabels2)
	s.metrics.EXPECT().MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency, telemetry.Error, telemetry.ElapsedTime},
		gomock.Any(), attestorLabels2)

	// No selectors expected
	selectors = s.attestor.Attest(ctx, 1)
	s.Empty(selectors)
}
