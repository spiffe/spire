package metricsservice

import (
	"context"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	metricsv0 "github.com/spiffe/spire/proto/spire/hostservice/common/metrics/v0"
)

type pluginMetrics struct {
	m           metricsv0.MetricsServiceClient
	log         hclog.Logger
	fixedLabels []*metricsv0.Label
}

// WrapPluginMetrics returns a Metrics implementation that wraps the Metrics Host Service
// Additionally, labels common to the module can also be set, and will be added to all
// resulting metrics calls.
// This enables usage of common functionality related to the Metrics interface from a plugin.
// Any errors are logged, but not returned.
func WrapPluginMetrics(m metricsv0.MetricsServiceClient, log hclog.Logger, labels ...telemetry.Label) telemetry.Metrics {
	return pluginMetrics{
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
	_, err := p.m.SetGauge(context.Background(), &metricsv0.SetGaugeRequest{
		Key:    key,
		Val:    val,
		Labels: append(convertToRPCLabels(labels), p.fixedLabels...),
	})

	if err != nil {
		p.log.Error("Error with metrics", telemetry.Error, err)
	}
}

// Should emit a Key/Value pair for each call
func (p pluginMetrics) EmitKey(key []string, val float32) {
	_, err := p.m.EmitKey(context.Background(), &metricsv0.EmitKeyRequest{
		Key: key,
		Val: val,
	})

	if err != nil {
		p.log.Error("Error with metrics", telemetry.Error, err)
	}
}

// Counters should accumulate values
func (p pluginMetrics) IncrCounter(key []string, val float32) {
	p.IncrCounterWithLabels(key, val, nil)
}

func (p pluginMetrics) IncrCounterWithLabels(key []string, val float32, labels []telemetry.Label) {
	_, err := p.m.IncrCounter(context.Background(), &metricsv0.IncrCounterRequest{
		Key:    key,
		Val:    val,
		Labels: append(convertToRPCLabels(labels), p.fixedLabels...),
	})

	if err != nil {
		p.log.Error("Error with metrics", telemetry.Error, err)
	}
}

// Samples are for timing information, where quantiles are used
func (p pluginMetrics) AddSample(key []string, val float32) {
	p.AddSampleWithLabels(key, val, nil)
}

func (p pluginMetrics) AddSampleWithLabels(key []string, val float32, labels []telemetry.Label) {
	_, err := p.m.AddSample(context.Background(), &metricsv0.AddSampleRequest{
		Key:    key,
		Val:    val,
		Labels: append(convertToRPCLabels(labels), p.fixedLabels...),
	})

	if err != nil {
		p.log.Error("Error with metrics", telemetry.Error, err)
	}
}

// A convenience function for measuring elapsed time with a single line
func (p pluginMetrics) MeasureSince(key []string, start time.Time) {
	p.MeasureSinceWithLabels(key, start, nil)
}

func (p pluginMetrics) MeasureSinceWithLabels(key []string, start time.Time, labels []telemetry.Label) {
	_, err := p.m.MeasureSince(context.Background(), &metricsv0.MeasureSinceRequest{
		Key:    key,
		Time:   start.UnixNano(),
		Labels: append(convertToRPCLabels(labels), p.fixedLabels...),
	})

	if err != nil {
		p.log.Error("Error with metrics", telemetry.Error, err)
	}
}
