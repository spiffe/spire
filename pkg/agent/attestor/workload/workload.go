package attestor

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_workload "github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"github.com/spiffe/spire/proto/spire/common"
)

type attestor struct {
	c *Config
}

type Attestor interface {
	Attest(ctx context.Context, pid int) []*common.Selector
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
func (wla *attestor) Attest(ctx context.Context, pid int) []*common.Selector {
	counter := telemetry_workload.StartAttestationCall(wla.c.Metrics)
	defer counter.Done(nil)

	log := wla.c.Log.WithField(telemetry.PID, pid)

	plugins := wla.c.Catalog.GetWorkloadAttestors()
	sChan := make(chan []*common.Selector)
	errChan := make(chan error)

	for _, p := range plugins {
		go func(p workloadattestor.WorkloadAttestor) {
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
	// The agent health check currently exercises the Workload API. Since this
	// can happen with some frequency, it has a tendency to fill up logs with
	// hard-to-filter details if we're not careful (e.g. issue #1537). Only log
	// if it is not the agent itself.
	if pid != os.Getpid() {
		log.WithField(telemetry.Selectors, selectors).Debug("PID attested to have selectors")
	}
	return selectors
}

// invokeAttestor invokes attestation against the supplied plugin. Should be called from a goroutine.
func (wla *attestor) invokeAttestor(ctx context.Context, a workloadattestor.WorkloadAttestor, pid int) (_ []*common.Selector, err error) {
	counter := telemetry_workload.StartAttestorCall(wla.c.Metrics, a.Name())
	defer counter.Done(&err)

	selectors, err := a.Attest(ctx, pid)
	if err != nil {
		return nil, fmt.Errorf("workload attestor %q failed: %w", a.Name(), err)
	}
	return selectors, nil
}
