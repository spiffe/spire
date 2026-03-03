package attestor

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_workload "github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/protobuf/types/known/anypb"
)

type attestor struct {
	c *Config
}

type Attestor interface {
	Attest(ctx context.Context, pid int) ([]*common.Selector, error)
	AttestReference(ctx context.Context, reference *anypb.Any) ([]*common.Selector, error)
}

func New(config *Config) Attestor {
	return newAttestor(config)
}

func newAttestor(config *Config) *attestor {
	if config.selectorHook == nil {
		config.selectorHook = func([]*common.Selector) {}
	}

	return &attestor{c: config}
}

type Config struct {
	Catalog catalog.Catalog
	Log     logrus.FieldLogger
	Metrics telemetry.Metrics

	// Test hook called when selectors are obtained from a workload attestor plugin
	selectorHook func([]*common.Selector)
}

// Attest invokes all workload attestor plugins against the provided PID. If an error
// is encountered, it is logged and selectors from the failing plugin are discarded.
func (wla *attestor) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	log := wla.c.Log.WithField(telemetry.PID, pid)

	return wla.attest(ctx, func(a workloadattestor.WorkloadAttestor) ([]*common.Selector, error) {
		var err error
		counter := telemetry_workload.StartAttestorCall(wla.c.Metrics, a.Name())
		defer counter.Done(&err)

		selectors, err := a.Attest(ctx, pid)
		if err != nil {
			log.WithError(err).Errorf("workload attestor %q failed", a.Name())
			return nil, fmt.Errorf("workload attestor %q failed: %w", a.Name(), err)
		}
		return selectors, nil
	})
}

func (wla *attestor) AttestReference(ctx context.Context, reference *anypb.Any) ([]*common.Selector, error) {
	// TODO(arndt) add references to log context
	log := wla.c.Log
	return wla.attest(ctx, func(a workloadattestor.WorkloadAttestor) ([]*common.Selector, error) {
		var err error
		counter := telemetry_workload.StartAttestorCall(wla.c.Metrics, a.Name())
		defer counter.Done(&err)

		selectors, err := a.AttestReference(ctx, reference)
		if err != nil {
			log.WithError(err).Errorf("workload attestor %q failed", a.Name())
			return nil, fmt.Errorf("workload attestor %q failed: %w", a.Name(), err)
		}
		return selectors, nil
	})
}

func (wla *attestor) attest(ctx context.Context, attestFunc func(attestor workloadattestor.WorkloadAttestor) ([]*common.Selector, error)) ([]*common.Selector, error) {
	counter := telemetry_workload.StartAttestationCall(wla.c.Metrics)
	defer counter.Done(nil)

	plugins := wla.c.Catalog.GetWorkloadAttestors()
	sChan := make(chan []*common.Selector)
	errChan := make(chan error)

	for _, p := range plugins {
		go func(p workloadattestor.WorkloadAttestor) {
			if selectors, err := attestFunc(p); err == nil {
				sChan <- selectors
			} else {
				errChan <- err
			}
		}(p)
	}

	// Collect the results
	selectors := []*common.Selector{}
	for range plugins {
		select {
		case s := <-sChan:
			selectors = append(selectors, s...)
			wla.c.selectorHook(selectors)
		case err := <-errChan:
			wla.c.Log.WithError(err).Error("Failed to collect all selectors")
		case <-ctx.Done():
			// If the client times out before all workload attestation plugins have reported selectors or an error,
			// it can be helpful to see the partial set of selectors discovered for debugging purposes.
			wla.c.Log.WithField(telemetry.PartialSelectors, selectors).Error("Timed out collecting selectors")
			return nil, ctx.Err()
		}
	}

	telemetry_workload.AddDiscoveredSelectorsSample(wla.c.Metrics, float32(len(selectors)))
	// // The agent health check currently exercises the Workload API. Since this
	// // can happen with some frequency, it has a tendency to fill up logs with
	// // hard-to-filter details if we're not careful (e.g. issue #1537). Only log
	// // if it is not the agent itself.
	// if pid != os.Getpid() {
	// 	log.WithField(telemetry.Selectors, selectors).Debug("PID attested to have selectors")
	// }
	return selectors, nil
}
