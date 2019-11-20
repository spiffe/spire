package attestor

import (
	"context"
	"fmt"

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
	Log     logrus.FieldLogger
	Metrics telemetry.Metrics
}

// Attest invokes all workload attestor plugins against the provided PID. If an error
// is encountered, it is logged and selectors from the failing plugin are discarded.
func (wla *attestor) Attest(ctx context.Context, pid int32) []*common.Selector {
	log := wla.c.Log.WithField(telemetry.PID, pid)

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
			log.WithError(err).Error("Failed to collect all selectors for PID")
		}
	}

	telemetry_workload.AddDiscoveredSelectorsSample(wla.c.Metrics, float32(len(selectors)))
	log.WithField(telemetry.Selectors, selectors).Debug("PID attested to have selectors")
	return selectors
}

// invokeAttestor invokes attestation against the supplied plugin. Should be called from a goroutine.
func (wla *attestor) invokeAttestor(ctx context.Context, a catalog.WorkloadAttestor, pid int32) (selectors []*common.Selector, err error) {
	req := &workloadattestor.AttestRequest{
		Pid: pid,
	}

	counter := telemetry_workload.StartAttestorCall(wla.c.Metrics, a.Name())
	defer counter.Done(&err)

	resp, err := a.Attest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("workload attestor %q failed: %v", a.Name(), err)
	}

	return resp.Selectors, nil
}
