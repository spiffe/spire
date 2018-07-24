package attestor

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/proto/common"
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
	T       telemetry.Sink
}

const (
	workloadApi    = "workload_api"
	workloadPid    = "workload_pid"
	workloadAttDur = "workload_attestation_duration"
)

// Attest invokes all workload attestor plugins against the provided PID. If an error
// is encountered, it is logged and selectors from the failing plugin are discarded.
func (wla *attestor) Attest(ctx context.Context, pid int32) []*common.Selector {
	tLabels := []telemetry.Label{{workloadPid, string(pid)}}
	defer wla.c.T.MeasureSinceWithLabels([]string{workloadApi, workloadAttDur}, time.Now(), tLabels)

	plugins := wla.c.Catalog.WorkloadAttestors()
	sChan := make(chan []*common.Selector)
	errChan := make(chan error)

	for _, p := range plugins {
		go func(p *catalog.ManagedWorkloadAttestor) {
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

	wla.c.T.AddSampleWithLabels([]string{workloadApi, "discovered_selectors"}, float32(len(selectors)), tLabels)
	wla.c.L.Debugf("PID %v attested to have selectors %v", pid, selectors)
	return selectors
}

// invokeAttestor invokes attestation against the supplied plugin. Should be called from a goroutine.
func (wla *attestor) invokeAttestor(ctx context.Context, a *catalog.ManagedWorkloadAttestor, pid int32) ([]*common.Selector, error) {
	attestorName := a.Config().PluginName
	tLabels := []telemetry.Label{{workloadPid, string(pid)}, {"attestor_name", attestorName}}

	req := &workloadattestor.AttestRequest{
		Pid: pid,
	}

	start := time.Now()
	resp, err := a.Attest(ctx, req)

	// Capture the attestor latency metrics regardless of whether an error condition was encountered or not
	wla.c.T.MeasureSinceWithLabels([]string{workloadApi, "workload_attestor_latency"}, start, tLabels)
	if err != nil {
		return nil, fmt.Errorf("workload attestor %q failed: %v", attestorName, err)
	}

	return resp.Selectors, nil
}
