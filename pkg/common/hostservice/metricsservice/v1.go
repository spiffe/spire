package metricsservice

import (
	"context"
	"time"

	metricsv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/common/metrics/v1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/protobuf/types/known/emptypb"
)

// V1 returns a v1 metrics service server over the provided Metrics interface
func V1(metrics telemetry.Metrics) metricsv1.MetricsServer {
	return metricsV1{metrics: metrics}
}

type metricsV1 struct {
	metricsv1.UnsafeMetricsServer
	metrics telemetry.Metrics
}

func (m metricsV1) AddSample(ctx context.Context, req *metricsv1.AddSampleRequest) (*emptypb.Empty, error) {
	labels := v1ConvertToTelemetryLabels(req.Labels)
	m.metrics.AddSampleWithLabels(req.Key, req.Val, labels)
	return &emptypb.Empty{}, nil
}

func (m metricsV1) EmitKey(ctx context.Context, req *metricsv1.EmitKeyRequest) (*emptypb.Empty, error) {
	m.metrics.EmitKey(req.Key, req.Val)
	return &emptypb.Empty{}, nil
}

func (m metricsV1) IncrCounter(ctx context.Context, req *metricsv1.IncrCounterRequest) (*emptypb.Empty, error) {
	labels := v1ConvertToTelemetryLabels(req.Labels)
	m.metrics.IncrCounterWithLabels(req.Key, req.Val, labels)
	return &emptypb.Empty{}, nil
}

func (m metricsV1) MeasureSince(ctx context.Context, req *metricsv1.MeasureSinceRequest) (*emptypb.Empty, error) {
	labels := v1ConvertToTelemetryLabels(req.Labels)
	m.metrics.MeasureSinceWithLabels(req.Key, time.Unix(0, req.Time), labels)
	return &emptypb.Empty{}, nil
}

func (m metricsV1) SetGauge(ctx context.Context, req *metricsv1.SetGaugeRequest) (*emptypb.Empty, error) {
	labels := v1ConvertToTelemetryLabels(req.Labels)
	m.metrics.SetGaugeWithLabels(req.Key, req.Val, labels)
	return &emptypb.Empty{}, nil
}

func v1ConvertToRPCLabels(inLabels []telemetry.Label) []*metricsv1.Label {
	labels := make([]*metricsv1.Label, 0, len(inLabels))
	for _, inLabel := range inLabels {
		labels = append(labels, &metricsv1.Label{
			Name:  inLabel.Name,
			Value: inLabel.Value,
		})
	}

	return labels
}

func v1ConvertToTelemetryLabels(inLabels []*metricsv1.Label) []telemetry.Label {
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
