package attestor

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/sirupsen/logrus"
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
		2: {"bar"},
		// 3: attestor1 cannot attest process 3
		4: {"bar"},
	}
	attestor2Pids = map[int32][]string{
		1: nil,
		2: nil,
		3: {"baz"},
		4: {"baz"},
		// 5: attestor2 cannot attest process 5
	}
)

func TestWorkloadAttestor(t *testing.T) {
	suite.Run(t, new(WorkloadAttestorTestSuite))
}

type WorkloadAttestorTestSuite struct {
	suite.Suite

	attestor   *attestor
	catalog    *fakeagentcatalog.Catalog
	loggerHook *test.Hook
}

func (s *WorkloadAttestorTestSuite) SetupTest() {
	log, hook := test.NewNullLogger()
	s.loggerHook = hook

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
	selectors, err := s.attestor.Attest(ctx, 1)
	s.Nil(err)
	s.Empty(selectors)

	// attestor1 has selectors, but not attestor2
	selectors, err = s.attestor.Attest(ctx, 2)
	s.Nil(err)
	spiretest.AssertProtoListEqual(s.T(), selectors1, selectors)

	// attestor2 has selectors, attestor1 fails
	selectors, err = s.attestor.Attest(ctx, 3)
	s.Nil(err)
	spiretest.AssertProtoListEqual(s.T(), selectors2, selectors)

	// both have selectors
	selectors, err = s.attestor.Attest(ctx, 4)
	s.Nil(err)
	util.SortSelectors(selectors)
	combined := slices.Concat(selectors1, selectors2)
	util.SortSelectors(combined)
	spiretest.AssertProtoListEqual(s.T(), combined, selectors)

	// neither attestor can attest the workload
	selectors, err = s.attestor.Attest(ctx, 5)
	spiretest.AssertErrorContains(s.T(), err, `workload attestor "fake1" failed`)
	spiretest.AssertErrorContains(s.T(), err, `workloadattestor(fake1): cannot attest pid 5`)
	spiretest.AssertErrorContains(s.T(), err, `workload attestor "fake2" failed`)
	spiretest.AssertErrorContains(s.T(), err, `workloadattestor(fake2): cannot attest pid 5`)
	s.Nil(selectors)
}

func (s *WorkloadAttestorTestSuite) TestAttestLogsOnPartialFailure() {
	s.catalog.SetWorkloadAttestors(
		fakeworkloadattestor.New(s.T(), "fake1", attestor1Pids),
		fakeworkloadattestor.New(s.T(), "fake2", attestor2Pids),
	)

	selectors, err := s.attestor.Attest(ctx, 3)
	s.Nil(err)
	spiretest.AssertProtoListEqual(s.T(), selectors2, selectors)
	spiretest.AssertLogs(s.T(), s.loggerHook.AllEntries(), []spiretest.LogEntry{
		{
			Level:   logrus.ErrorLevel,
			Message: "Failed to collect all selectors for PID",
			Data: logrus.Fields{
				telemetry.PID:   "3",
				logrus.ErrorKey: `workload attestor "fake1" failed: rpc error: code = Unknown desc = workloadattestor(fake1): cannot attest pid 3`,
			},
		},
	})
}

func (s *WorkloadAttestorTestSuite) TestAttestWorkloadMetrics() {
	// Add only one attestor
	s.catalog.SetWorkloadAttestors(
		fakeworkloadattestor.New(s.T(), "fake1", attestor1Pids),
	)

	// Use fake metrics
	metrics := fakemetrics.New()
	s.attestor.c.Metrics = metrics

	selectors, err := s.attestor.Attest(ctx, 2)
	s.Nil(err)

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
	selectors, err = s.attestor.Attest(ctx, 3)
	spiretest.AssertErrorContains(s.T(), err, `workload attestor "fake1" failed`)
	spiretest.AssertErrorContains(s.T(), err, `workloadattestor(fake1): cannot attest pid 3`)
	s.Empty(selectors)

	// Create expected metrics with error key
	expected = fakemetrics.New()
	err = errors.New("some error")
	attestorCounter = telemetry_workload.StartAttestorCall(expected, "fake1")
	attestorCounter.Done(&err)
	attestationCounter = telemetry_workload.StartAttestationCall(expected)
	attestationCounter.Done(&err)

	s.Require().Equal(expected.AllMetrics(), metrics.AllMetrics())
}

func (s *WorkloadAttestorTestSuite) TestAttestLogsOnContextCancellation() {
	pid := 4
	selectorC := make(chan []*common.Selector, 1)
	s.attestor.c.selectorHook = func(selectors []*common.Selector) {
		selectorC <- selectors
	}

	pluginC := make(chan struct{}, 1)
	// Add one attestor that provides selectors and another that doesn't return before the test context is cancelled
	s.catalog.SetWorkloadAttestors(
		fakeworkloadattestor.New(s.T(), "fake1", attestor1Pids),
		fakeworkloadattestor.NewTimeoutAttestor(s.T(), "faketimeoutattestor", pluginC),
	)

	defer func() {
		// Unblock attestor that is blocking on channel
		pluginC <- struct{}{}
	}()

	attestCh := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	var selectors []*common.Selector
	var attestErr error
	go func() {
		selectors, attestErr = s.attestor.Attest(ctx, pid)
		attestCh <- struct{}{}
	}()

	// Wait for one of the plugins to return selectors
	<-selectorC

	// Cancel context to simulate caller hanging up in the middle of workload attestation
	cancel()

	// Wait for attestation goroutine to complete execution
	<-attestCh

	s.Nil(selectors)
	s.Error(attestErr)
	spiretest.AssertLogs(s.T(), s.loggerHook.AllEntries(), []spiretest.LogEntry{
		{
			Level:   logrus.ErrorLevel,
			Message: "Timed out collecting selectors for PID",
			Data: logrus.Fields{
				telemetry.PID:   fmt.Sprint(pid),
				logrus.ErrorKey: context.Canceled.Error(),
			},
		},
	})
}
