package attestor

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_workload "github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
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
	defer telemetry_workload.MeasureAttestDuration(wla.c.M, time.Now())

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

	telemetry_workload.AddDiscoveredSelectorsSample(wla.c.M, float32(len(selectors)))
	wla.c.L.Debugf("PID %v attested to have selectors %v", pid, selectors)
	return selectors
}

// invokeAttestor invokes attestation against the supplied plugin. Should be called from a goroutine.
func (wla *attestor) invokeAttestor(ctx context.Context, a catalog.WorkloadAttestor, pid int32) (selectors []*common.Selector, err error) {
	req := &workloadattestor.AttestRequest{
		Pid: pid,
	}

	counter := telemetry_workload.StartAttestorLatencyCall(wla.c.M, a.Name())
	defer counter.Done(&err)

	resp, err := a.Attest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("workload attestor %q failed: %v", a.Name(), err)
	}

	return resp.Selectors, nil
}
