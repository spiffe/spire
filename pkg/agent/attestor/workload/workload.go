package attestor

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/agent/workloadattestor"
	"github.com/spiffe/spire/proto/spire/common"
)

type attestor struct {
	c *Config
}

type Attestor interface {
	Attest(ctx context.Context, pid int32) []*common.Selector
}

func New(config *Config) Attestor {
	return newAttestor(config)
}

func newAttestor(config *Config) *attestor {
	return &attestor{c: config}
}

type Config struct {
	Catalog catalog.Catalog
	L       logrus.FieldLogger
	M       telemetry.Metrics
}

// Attest invokes all workload attestor plugins against the provided PID. If an error
// is encountered, it is logged and selectors from the failing plugin are discarded.
func (wla *attestor) Attest(ctx context.Context, pid int32) []*common.Selector {
	defer wla.c.M.MeasureSince([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestationDuration}, time.Now())

	plugins := wla.c.Catalog.GetWorkloadAttestors()
	sChan := make(chan []*common.Selector)
	errChan := make(chan error)

	for _, p := range plugins {
		go func(p catalog.WorkloadAttestor) {
			if selectors, err := wla.invokeAttestor(ctx, p, pid); err == nil {
				sChan <- selectors
			} else {
				errChan <- err
			}
		}(p)
	}

	// Collect the results
	selectors := []*common.Selector{}
	for i := 0; i < len(plugins); i++ {
		select {
		case s := <-sChan:
			selectors = append(selectors, s...)
		case err := <-errChan:
			wla.c.L.Errorf("Failed to collect all selectors for PID %v: %v", pid, err)
		}
	}

	wla.c.M.AddSample([]string{telemetry.WorkloadAPI, telemetry.DiscoveredSelectors}, float32(len(selectors)))
	wla.c.L.Debugf("PID %v attested to have selectors %v", pid, selectors)
	return selectors
}

// invokeAttestor invokes attestation against the supplied plugin. Should be called from a goroutine.
func (wla *attestor) invokeAttestor(ctx context.Context, a catalog.WorkloadAttestor, pid int32) ([]*common.Selector, error) {
	tLabels := []telemetry.Label{{telemetry.AttestorName, a.Name()}}

	req := &workloadattestor.AttestRequest{
		Pid: pid,
	}

	start := time.Now()
	resp, err := a.Attest(ctx, req)

	// Capture the attestor latency metrics regardless of whether an error condition was encountered or not
	wla.c.M.MeasureSinceWithLabels([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency}, start, tLabels)
	if err != nil {
		return nil, fmt.Errorf("workload attestor %q failed: %v", a.Name(), err)
	}

	return resp.Selectors, nil
}
