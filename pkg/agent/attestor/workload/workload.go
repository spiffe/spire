package attestor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_workload "github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

var errReferenceUnsupported = errors.New("workload reference type unsupported by attestor")

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

// Attest invokes all workload attestor plugins against the provided PID. If some
// attestors fail, the errors are logged and selectors from the failing plugins
// are discarded. If all attestors fail, the combined error is returned.
func (wla *attestor) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	log := wla.c.Log.WithField(telemetry.PID, pid)

	selectors, err := wla.attest(ctx, func(a workloadattestor.WorkloadAttestor) ([]*common.Selector, error) {
		var err error
		counter := telemetry_workload.StartAttestorCall(wla.c.Metrics, a.Name())
		defer counter.Done(&err)

		selectors, err := a.Attest(ctx, pid)
		if err != nil {
			log.WithError(err).Errorf("workload attestor %q failed", a.Name())
			return nil, fmt.Errorf("workload attestor %q failed: %w", a.Name(), err)
		}
		return selectors, nil
	}, nil, nil)
	if err != nil {
		return nil, err
	}

	// The agent health check currently exercises the Workload API. Since this
	// can happen with some frequency, it has a tendency to fill up logs with
	// hard-to-filter details if we're not careful (e.g. issue #1537). Only log
	// if it is not the agent itself.
	if pid != os.Getpid() {
		log.WithField(telemetry.Selectors, selectors).Debug("PID attested to have selectors")
	}

	return selectors, nil
}

func (wla *attestor) AttestReference(ctx context.Context, reference *anypb.Any) ([]*common.Selector, error) {
	log := wla.c.Log.WithField(telemetry.ReferenceType, reference.GetTypeUrl())
	selectors, err := wla.attest(ctx, func(a workloadattestor.WorkloadAttestor) ([]*common.Selector, error) {
		var err error
		counter := telemetry_workload.StartAttestorCall(wla.c.Metrics, a.Name())
		defer counter.Done(&err)

		selectors, err := a.AttestReference(ctx, reference)
		if err != nil {
			if status.Code(err) == codes.Unimplemented {
				log.WithError(err).Debugf("workload attestor %q does not support reference attestation", a.Name())
				err = nil
				return nil, errReferenceUnsupported
			}
			log.WithError(err).Errorf("workload attestor %q failed", a.Name())
			return nil, fmt.Errorf("workload attestor %q failed: %w", a.Name(), err)
		}
		return selectors, nil
	}, errReferenceUnsupported, status.Error(codes.Unimplemented, "no workload attestor handled reference"))
	if err != nil {
		return nil, err
	}
	log.WithField(telemetry.Selectors, selectors).Debug("Reference attested to have selectors")
	return selectors, nil
}

func (wla *attestor) attest(ctx context.Context, attestFunc func(attestor workloadattestor.WorkloadAttestor) ([]*common.Selector, error), skippableErr error, allSkippedErr error) (_ []*common.Selector, retErr error) {
	counter := telemetry_workload.StartAttestationCall(wla.c.Metrics)
	defer counter.Done(&retErr)

	plugins := wla.c.Catalog.GetWorkloadAttestors()
	// Buffered so plugin goroutines never block sending if the outer loop
	// returns early (e.g., on ctx cancellation). Combined with the deferred
	// wg.Wait() below, this guarantees plugin-level logs are flushed before
	// we return to the caller.
	sChan := make(chan []*common.Selector, len(plugins))
	errChan := make(chan error, len(plugins))

	var wg sync.WaitGroup
	for _, p := range plugins {
		wg.Go(func() {
			if selectors, err := attestFunc(p); err == nil {
				sChan <- selectors
			} else {
				errChan <- err
			}
		})
	}
	defer wg.Wait()

	// Collect the results
	selectors := []*common.Selector{}
	successes := 0
	skipped := 0
	var errs []error
	for range plugins {
		select {
		case s := <-sChan:
			successes++
			selectors = append(selectors, s...)
			wla.c.selectorHook(selectors)
		case err := <-errChan:
			if ctx.Err() != nil {
				wla.c.Log.WithError(ctx.Err()).Error("Timed out collecting selectors")
				return nil, ctx.Err()
			}
			if skippableErr != nil && errors.Is(err, skippableErr) {
				skipped++
				continue
			}
			errs = append(errs, err)
		case <-ctx.Done():
			wla.c.Log.WithError(ctx.Err()).Error("Timed out collecting selectors")
			return nil, ctx.Err()
		}
	}

	if len(plugins) > 0 && successes == 0 {
		if len(errs) > 0 {
			return nil, errors.Join(errs...)
		}
		if skipped > 0 && allSkippedErr != nil {
			return nil, allSkippedErr
		}
	}

	if len(errs) > 0 {
		wla.c.Log.WithError(errors.Join(errs...)).Error("Failed to collect all selectors")
	}

	telemetry_workload.AddDiscoveredSelectorsSample(wla.c.Metrics, float32(len(selectors)))
	return selectors, nil
}
