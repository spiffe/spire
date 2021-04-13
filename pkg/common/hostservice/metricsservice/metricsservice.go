package metricsservice

import (
	"context"
	"time"

	"github.com/spiffe/spire/pkg/common/telemetry"
	metricsv0 "github.com/spiffe/spire/proto/spire/hostservice/common/metrics/v0"
)

// Config for the metrics host service
type Config struct {
	Metrics telemetry.Metrics
}

type metricsService struct {
	metricsv0.UnsafeMetricsServiceServer

	cfg Config
}

// New create and return new Metrics Service
func New(cfg Config) metricsv0.MetricsServiceServer {
	return metricsService{
		cfg: cfg,
	}
}

func (m metricsService) AddSample(ctx context.Context, req *metricsv0.AddSampleRequest) (*metricsv0.AddSampleResponse, error) {
	labels := convertToTelemetryLabels(req.Labels)
	m.cfg.Metrics.AddSampleWithLabels(req.Key, req.Val, labels)
	return &metricsv0.AddSampleResponse{}, nil
}

func (m metricsService) EmitKey(ctx context.Context, req *metricsv0.EmitKeyRequest) (*metricsv0.EmitKeyResponse, error) {
	m.cfg.Metrics.EmitKey(req.Key, req.Val)
	return &metricsv0.EmitKeyResponse{}, nil
}

func (m metricsService) IncrCounter(ctx context.Context, req *metricsv0.IncrCounterRequest) (*metricsv0.IncrCounterResponse, error) {
	labels := convertToTelemetryLabels(req.Labels)
	m.cfg.Metrics.IncrCounterWithLabels(req.Key, req.Val, labels)
	return &metricsv0.IncrCounterResponse{}, nil
}

func (m metricsService) MeasureSince(ctx context.Context, req *metricsv0.MeasureSinceRequest) (*metricsv0.MeasureSinceResponse, error) {
	labels := convertToTelemetryLabels(req.Labels)
	m.cfg.Metrics.MeasureSinceWithLabels(req.Key, time.Unix(0, req.Time), labels)
	return &metricsv0.MeasureSinceResponse{}, nil
}

func (m metricsService) SetGauge(ctx context.Context, req *metricsv0.SetGaugeRequest) (*metricsv0.SetGaugeResponse, error) {
	labels := convertToTelemetryLabels(req.Labels)
	m.cfg.Metrics.SetGaugeWithLabels(req.Key, req.Val, labels)
	return &metricsv0.SetGaugeResponse{}, nil
}

func convertToRPCLabels(inLabels []telemetry.Label) []*metricsv0.Label {
	labels := make([]*metricsv0.Label, 0, len(inLabels))
	for _, inLabel := range inLabels {
		labels = append(labels, &metricsv0.Label{
			Name:  inLabel.Name,
			Value: inLabel.Value,
		})
	}

	return labels
}

func convertToTelemetryLabels(inLabels []*metricsv0.Label) []telemetry.Label {
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
