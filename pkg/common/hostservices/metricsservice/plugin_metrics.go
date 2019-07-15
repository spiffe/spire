package metricsservice

import (
	"context"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common/hostservices"
)

type pluginMetrics struct {
	ctx         context.Context
	m           hostservices.MetricsService
	log         hclog.Logger
	fixedLabels []*hostservices.Label
}

// WrapPluginMetricsForContext returns a Metrics implementation that wraps the Metrics Host Service
// and passes in the given context to that service. Additionally, labels common to the context
// can also be set, and will be added to all resulting metrics calls.
// This enables usage of common functionality related to the Metrics interface from a plugin.
// Any errors are logged, but not returned.
func WrapPluginMetricsForContext(ctx context.Context, m hostservices.MetricsService, log hclog.Logger, labels ...telemetry.Label) telemetry.Metrics {
	return pluginMetrics{
		ctx:         ctx,
		m:           m,
		log:         log,
		fixedLabels: convertToRPCLabels(labels),
	}
}

// A Gauge should retain the last value it is set to
func (p pluginMetrics) SetGauge(key []string, val float32) {
	p.SetGaugeWithLabels(key, val, nil)
}

func (p pluginMetrics) SetGaugeWithLabels(key []string, val float32, labels []telemetry.Label) {
	_, err := p.m.SetGauge(p.ctx, &hostservices.SetGaugeRequest{
		Key:    key,
		Val:    val,
		Labels: append(convertToRPCLabels(labels), p.fixedLabels...),
	})

	if err != nil {
		p.log.Error("error with metrics", telemetry.Error, err)
	}
}

// Should emit a Key/Value pair for each call
func (p pluginMetrics) EmitKey(key []string, val float32) {
	_, err := p.m.EmitKey(p.ctx, &hostservices.EmitKeyRequest{
		Key: key,
		Val: val,
	})

	if err != nil {
		p.log.Error("error with metrics", telemetry.Error, err)
	}
}

// Counters should accumulate values
func (p pluginMetrics) IncrCounter(key []string, val float32) {
	p.IncrCounterWithLabels(key, val, nil)
}

func (p pluginMetrics) IncrCounterWithLabels(key []string, val float32, labels []telemetry.Label) {
	_, err := p.m.IncrCounter(p.ctx, &hostservices.IncrCounterRequest{
		Key:    key,
		Val:    val,
		Labels: append(convertToRPCLabels(labels), p.fixedLabels...),
	})

	if err != nil {
		p.log.Error("error with metrics", telemetry.Error, err)
	}
}

// Samples are for timing information, where quantiles are used
func (p pluginMetrics) AddSample(key []string, val float32) {
	p.AddSampleWithLabels(key, val, nil)
}

func (p pluginMetrics) AddSampleWithLabels(key []string, val float32, labels []telemetry.Label) {
	_, err := p.m.AddSample(p.ctx, &hostservices.AddSampleRequest{
		Key:    key,
		Val:    val,
		Labels: append(convertToRPCLabels(labels), p.fixedLabels...),
	})

	if err != nil {
		p.log.Error("error with metrics", telemetry.Error, err)
	}
}

// A convenience function for measuring elapsed time with a single line
func (p pluginMetrics) MeasureSince(key []string, start time.Time) {
	p.MeasureSinceWithLabels(key, start, nil)
}

func (p pluginMetrics) MeasureSinceWithLabels(key []string, start time.Time, labels []telemetry.Label) {
	_, err := p.m.MeasureSince(p.ctx, &hostservices.MeasureSinceRequest{
		Key:    key,
		Time:   start.UnixNano(),
		Labels: append(convertToRPCLabels(labels), p.fixedLabels...),
	})

	if err != nil {
		p.log.Error("error with metrics", telemetry.Error, err)
	}
}
