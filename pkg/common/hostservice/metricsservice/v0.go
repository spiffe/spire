package metricsservice

import (
	"context"
	"time"

	"github.com/spiffe/spire/pkg/common/telemetry"
	metricsv0 "github.com/spiffe/spire/proto/spire/hostservice/common/metrics/v0"
)

// V0 returns a v0 metrics service server over the provided Metrics interface
func V0(metrics telemetry.Metrics) metricsv0.MetricsServiceServer {
	return metricsV0{metrics: metrics}
}

type metricsV0 struct {
	metricsv0.UnsafeMetricsServiceServer
	metrics telemetry.Metrics
}

func (m metricsV0) AddSample(ctx context.Context, req *metricsv0.AddSampleRequest) (*metricsv0.AddSampleResponse, error) {
	labels := v0ConvertToTelemetryLabels(req.Labels)
	m.metrics.AddSampleWithLabels(req.Key, req.Val, labels)
	return &metricsv0.AddSampleResponse{}, nil
}

func (m metricsV0) EmitKey(ctx context.Context, req *metricsv0.EmitKeyRequest) (*metricsv0.EmitKeyResponse, error) {
	m.metrics.EmitKey(req.Key, req.Val)
	return &metricsv0.EmitKeyResponse{}, nil
}

func (m metricsV0) IncrCounter(ctx context.Context, req *metricsv0.IncrCounterRequest) (*metricsv0.IncrCounterResponse, error) {
	labels := v0ConvertToTelemetryLabels(req.Labels)
	m.metrics.IncrCounterWithLabels(req.Key, req.Val, labels)
	return &metricsv0.IncrCounterResponse{}, nil
}

func (m metricsV0) MeasureSince(ctx context.Context, req *metricsv0.MeasureSinceRequest) (*metricsv0.MeasureSinceResponse, error) {
	labels := v0ConvertToTelemetryLabels(req.Labels)
	m.metrics.MeasureSinceWithLabels(req.Key, time.Unix(0, req.Time), labels)
	return &metricsv0.MeasureSinceResponse{}, nil
}

func (m metricsV0) SetGauge(ctx context.Context, req *metricsv0.SetGaugeRequest) (*metricsv0.SetGaugeResponse, error) {
	labels := v0ConvertToTelemetryLabels(req.Labels)
	m.metrics.SetGaugeWithLabels(req.Key, req.Val, labels)
	return &metricsv0.SetGaugeResponse{}, nil
}

func v0ConvertToRPCLabels(inLabels []telemetry.Label) []*metricsv0.Label {
	labels := make([]*metricsv0.Label, 0, len(inLabels))
	for _, inLabel := range inLabels {
		labels = append(labels, &metricsv0.Label{
			Name:  inLabel.Name,
			Value: inLabel.Value,
		})
	}

	return labels
}

func v0ConvertToTelemetryLabels(inLabels []*metricsv0.Label) []telemetry.Label {
	labels := make([]telemetry.Label, 0, len(inLabels))
	for _, inLabel := range inLabels {
		if inLabel != nil {
			labels = append(labels, telemetry.Label{
				Name:  inLabel.Name,
				Value: inLabel.Value,
			})
		}
	}

	return labels
}
