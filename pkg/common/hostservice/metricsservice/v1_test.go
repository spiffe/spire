package metricsservice

import (
	"context"
	"testing"
	"time"

	metricsv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/common/metrics/v1"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
)

func TestV1SetGauge(t *testing.T) {
	tests := []struct {
		desc string
		req  *metricsv1.SetGaugeRequest
	}{
		{
			desc: "no labels",
			req: &metricsv1.SetGaugeRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "one label",
			req: &metricsv1.SetGaugeRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
				Labels: []*metricsv1.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &metricsv1.SetGaugeRequest{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.SetGaugeWithLabels(tt.req.Key, tt.req.Val, v1ConvertToTelemetryLabels(tt.req.Labels))

			service, actual := setupV1()
			_, err := service.SetGauge(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestV1MeasureSince(t *testing.T) {
	tests := []struct {
		desc string
		req  *metricsv1.MeasureSinceRequest
	}{
		{
			desc: "no labels",
			req: &metricsv1.MeasureSinceRequest{
				Key:  []string{"key1", "key2"},
				Time: time.Now().Unix(),
			},
		},
		{
			desc: "one label",
			req: &metricsv1.MeasureSinceRequest{
				Key:  []string{"key1", "key2"},
				Time: time.Now().Unix(),
				Labels: []*metricsv1.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &metricsv1.MeasureSinceRequest{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.MeasureSinceWithLabels(tt.req.Key, time.Unix(0, tt.req.Time), v1ConvertToTelemetryLabels(tt.req.Labels))

			service, actual := setupV1()
			_, err := service.MeasureSince(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestV1IncrCounter(t *testing.T) {
	tests := []struct {
		desc string
		req  *metricsv1.IncrCounterRequest
	}{
		{
			desc: "no labels",
			req: &metricsv1.IncrCounterRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "one label",
			req: &metricsv1.IncrCounterRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
				Labels: []*metricsv1.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &metricsv1.IncrCounterRequest{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.IncrCounterWithLabels(tt.req.Key, tt.req.Val, v1ConvertToTelemetryLabels(tt.req.Labels))

			service, actual := setupV1()
			_, err := service.IncrCounter(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestV1AddSample(t *testing.T) {
	tests := []struct {
		desc string
		req  *metricsv1.AddSampleRequest
	}{
		{
			desc: "no labels",
			req: &metricsv1.AddSampleRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "one label",
			req: &metricsv1.AddSampleRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
				Labels: []*metricsv1.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &metricsv1.AddSampleRequest{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.AddSampleWithLabels(tt.req.Key, tt.req.Val, v1ConvertToTelemetryLabels(tt.req.Labels))

			service, actual := setupV1()
			_, err := service.AddSample(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestV1EmitKey(t *testing.T) {
	tests := []struct {
		desc string
		req  *metricsv1.EmitKeyRequest
	}{
		{
			desc: "normal request",
			req: &metricsv1.EmitKeyRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "empty request",
			req:  &metricsv1.EmitKeyRequest{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.EmitKey(tt.req.Key, tt.req.Val)

			service, actual := setupV1()
			_, err := service.EmitKey(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestV1ConvertToTelemetryLabels(t *testing.T) {
	tests := []struct {
		desc         string
		inLabels     []*metricsv1.Label
		expectLabels []telemetry.Label
	}{
		{
			desc:         "nil input",
			expectLabels: []telemetry.Label{},
		},
		{
			desc:         "empty input",
			inLabels:     []*metricsv1.Label{},
			expectLabels: []telemetry.Label{},
		},
		{
			desc: "one label",
			inLabels: []*metricsv1.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
			},
			expectLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
			},
		},
		{
			desc: "two labels",
			inLabels: []*metricsv1.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
				{
					Name:  "labelB",
					Value: "val3",
				},
			},
			expectLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
				{
					Name:  "labelB",
					Value: "val3",
				},
			},
		},
		{
			desc: "empty label",
			inLabels: []*metricsv1.Label{
				{},
			},
			expectLabels: []telemetry.Label{
				{
					Name:  "",
					Value: "",
				},
			},
		},
		{
			desc: "nil label skipped",
			inLabels: []*metricsv1.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
				nil,
				{
					Name:  "labelB",
					Value: "val3",
				},
			},
			expectLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
				{
					Name:  "labelB",
					Value: "val3",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			outLabels := v1ConvertToTelemetryLabels(tt.inLabels)

			assert.Equal(t, tt.expectLabels, outLabels)
		})
	}
}

func TestV1ConvertToRPCLabels(t *testing.T) {
	tests := []struct {
		desc         string
		inLabels     []telemetry.Label
		expectLabels []*metricsv1.Label
	}{
		{
			desc:         "nil input",
			expectLabels: []*metricsv1.Label{},
		},
		{
			desc:         "empty input",
			inLabels:     []telemetry.Label{},
			expectLabels: []*metricsv1.Label{},
		},
		{
			desc: "one label",
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
			},
			expectLabels: []*metricsv1.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
			},
		},
		{
			desc: "two labels",
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
				{
					Name:  "labelB",
					Value: "val3",
				},
			},
			expectLabels: []*metricsv1.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
				{
					Name:  "labelB",
					Value: "val3",
				},
			},
		},
		{
			desc: "empty label",
			inLabels: []telemetry.Label{
				{},
			},
			expectLabels: []*metricsv1.Label{
				{
					Name:  "",
					Value: "",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			outLabels := v1ConvertToRPCLabels(tt.inLabels)

			assert.Equal(t, tt.expectLabels, outLabels)
		})
	}
}

func setupV1() (metricsv1.MetricsServer, *fakemetrics.FakeMetrics) {
	metrics := fakemetrics.New()
	return V1(metrics), metrics
}
