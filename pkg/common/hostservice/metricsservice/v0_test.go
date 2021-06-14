package metricsservice

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/telemetry"
	metricsv0 "github.com/spiffe/spire/proto/spire/hostservice/common/metrics/v0"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
)

func TestV0SetGauge(t *testing.T) {
	tests := []struct {
		desc string
		req  *metricsv0.SetGaugeRequest
	}{
		{
			desc: "no labels",
			req: &metricsv0.SetGaugeRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "one label",
			req: &metricsv0.SetGaugeRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
				Labels: []*metricsv0.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &metricsv0.SetGaugeRequest{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.SetGaugeWithLabels(tt.req.Key, tt.req.Val, v0ConvertToTelemetryLabels(tt.req.Labels))

			service, actual := setupV0()
			resp, err := service.SetGauge(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, &metricsv0.SetGaugeResponse{}, resp)
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestV0MeasureSince(t *testing.T) {
	tests := []struct {
		desc string
		req  *metricsv0.MeasureSinceRequest
	}{
		{
			desc: "no labels",
			req: &metricsv0.MeasureSinceRequest{
				Key:  []string{"key1", "key2"},
				Time: time.Now().Unix(),
			},
		},
		{
			desc: "one label",
			req: &metricsv0.MeasureSinceRequest{
				Key:  []string{"key1", "key2"},
				Time: time.Now().Unix(),
				Labels: []*metricsv0.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &metricsv0.MeasureSinceRequest{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.MeasureSinceWithLabels(tt.req.Key, time.Unix(0, tt.req.Time), v0ConvertToTelemetryLabels(tt.req.Labels))

			service, actual := setupV0()
			resp, err := service.MeasureSince(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, &metricsv0.MeasureSinceResponse{}, resp)
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestV0IncrCounter(t *testing.T) {
	tests := []struct {
		desc string
		req  *metricsv0.IncrCounterRequest
	}{
		{
			desc: "no labels",
			req: &metricsv0.IncrCounterRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "one label",
			req: &metricsv0.IncrCounterRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
				Labels: []*metricsv0.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &metricsv0.IncrCounterRequest{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.IncrCounterWithLabels(tt.req.Key, tt.req.Val, v0ConvertToTelemetryLabels(tt.req.Labels))

			service, actual := setupV0()
			resp, err := service.IncrCounter(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, &metricsv0.IncrCounterResponse{}, resp)
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestV0AddSample(t *testing.T) {
	tests := []struct {
		desc string
		req  *metricsv0.AddSampleRequest
	}{
		{
			desc: "no labels",
			req: &metricsv0.AddSampleRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "one label",
			req: &metricsv0.AddSampleRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
				Labels: []*metricsv0.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &metricsv0.AddSampleRequest{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.AddSampleWithLabels(tt.req.Key, tt.req.Val, v0ConvertToTelemetryLabels(tt.req.Labels))

			service, actual := setupV0()
			resp, err := service.AddSample(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, &metricsv0.AddSampleResponse{}, resp)
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestV0EmitKey(t *testing.T) {
	tests := []struct {
		desc string
		req  *metricsv0.EmitKeyRequest
	}{
		{
			desc: "normal request",
			req: &metricsv0.EmitKeyRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "empty request",
			req:  &metricsv0.EmitKeyRequest{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.EmitKey(tt.req.Key, tt.req.Val)

			service, actual := setupV0()
			resp, err := service.EmitKey(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, &metricsv0.EmitKeyResponse{}, resp)
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestV0ConvertToTelemetryLabels(t *testing.T) {
	tests := []struct {
		desc         string
		inLabels     []*metricsv0.Label
		expectLabels []telemetry.Label
	}{
		{
			desc:         "nil input",
			expectLabels: []telemetry.Label{},
		},
		{
			desc:         "empty input",
			inLabels:     []*metricsv0.Label{},
			expectLabels: []telemetry.Label{},
		},
		{
			desc: "one label",
			inLabels: []*metricsv0.Label{
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
			inLabels: []*metricsv0.Label{
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
			inLabels: []*metricsv0.Label{
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
			inLabels: []*metricsv0.Label{
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
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			outLabels := v0ConvertToTelemetryLabels(tt.inLabels)

			assert.Equal(t, tt.expectLabels, outLabels)
		})
	}
}

func TestV0ConvertToRPCLabels(t *testing.T) {
	tests := []struct {
		desc         string
		inLabels     []telemetry.Label
		expectLabels []*metricsv0.Label
	}{
		{
			desc:         "nil input",
			expectLabels: []*metricsv0.Label{},
		},
		{
			desc:         "empty input",
			inLabels:     []telemetry.Label{},
			expectLabels: []*metricsv0.Label{},
		},
		{
			desc: "one label",
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
			},
			expectLabels: []*metricsv0.Label{
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
			expectLabels: []*metricsv0.Label{
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
			expectLabels: []*metricsv0.Label{
				{
					Name:  "",
					Value: "",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			outLabels := v0ConvertToRPCLabels(tt.inLabels)

			assert.Equal(t, tt.expectLabels, outLabels)
		})
	}
}

func setupV0() (metricsv0.MetricsServiceServer, *fakemetrics.FakeMetrics) {
	metrics := fakemetrics.New()
	return V0(metrics), metrics
}
