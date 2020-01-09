package metricsservice

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/common/plugin/hostservices"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/assert"
)

func setupMetricsService() (hostservices.MetricsService, *fakemetrics.FakeMetrics) {
	metrics := fakemetrics.New()
	return New(Config{
		Metrics: metrics,
	}), metrics
}

func TestSetGauge(t *testing.T) {
	tests := []struct {
		desc string
		req  *hostservices.SetGaugeRequest
	}{
		{
			desc: "no labels",
			req: &hostservices.SetGaugeRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "one label",
			req: &hostservices.SetGaugeRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
				Labels: []*hostservices.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &hostservices.SetGaugeRequest{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.SetGaugeWithLabels(tt.req.Key, tt.req.Val, convertToTelemetryLabels(tt.req.Labels))

			service, actual := setupMetricsService()
			resp, err := service.SetGauge(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, &hostservices.SetGaugeResponse{}, resp)
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestMeasureSince(t *testing.T) {
	tests := []struct {
		desc string
		req  *hostservices.MeasureSinceRequest
	}{
		{
			desc: "no labels",
			req: &hostservices.MeasureSinceRequest{
				Key:  []string{"key1", "key2"},
				Time: time.Now().Unix(),
			},
		},
		{
			desc: "one label",
			req: &hostservices.MeasureSinceRequest{
				Key:  []string{"key1", "key2"},
				Time: time.Now().Unix(),
				Labels: []*hostservices.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &hostservices.MeasureSinceRequest{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.MeasureSinceWithLabels(tt.req.Key, time.Unix(0, tt.req.Time), convertToTelemetryLabels(tt.req.Labels))

			service, actual := setupMetricsService()
			resp, err := service.MeasureSince(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, &hostservices.MeasureSinceResponse{}, resp)
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestIncrCounter(t *testing.T) {
	tests := []struct {
		desc string
		req  *hostservices.IncrCounterRequest
	}{
		{
			desc: "no labels",
			req: &hostservices.IncrCounterRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "one label",
			req: &hostservices.IncrCounterRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
				Labels: []*hostservices.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &hostservices.IncrCounterRequest{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.IncrCounterWithLabels(tt.req.Key, tt.req.Val, convertToTelemetryLabels(tt.req.Labels))

			service, actual := setupMetricsService()
			resp, err := service.IncrCounter(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, &hostservices.IncrCounterResponse{}, resp)
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestAddSample(t *testing.T) {
	tests := []struct {
		desc string
		req  *hostservices.AddSampleRequest
	}{
		{
			desc: "no labels",
			req: &hostservices.AddSampleRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "one label",
			req: &hostservices.AddSampleRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
				Labels: []*hostservices.Label{
					{
						Name:  "label1",
						Value: "val1",
					},
				},
			},
		},
		{
			desc: "empty request",
			req:  &hostservices.AddSampleRequest{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.AddSampleWithLabels(tt.req.Key, tt.req.Val, convertToTelemetryLabels(tt.req.Labels))

			service, actual := setupMetricsService()
			resp, err := service.AddSample(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, &hostservices.AddSampleResponse{}, resp)
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestEmitKey(t *testing.T) {
	tests := []struct {
		desc string
		req  *hostservices.EmitKeyRequest
	}{
		{
			desc: "normal request",
			req: &hostservices.EmitKeyRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
		},
		{
			desc: "empty request",
			req:  &hostservices.EmitKeyRequest{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.EmitKey(tt.req.Key, tt.req.Val)

			service, actual := setupMetricsService()
			resp, err := service.EmitKey(context.Background(), tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, &hostservices.EmitKeyResponse{}, resp)
				assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
			}
		})
	}
}

func TestConvertToTelemetryLabels(t *testing.T) {
	tests := []struct {
		desc         string
		inLabels     []*hostservices.Label
		expectLabels []telemetry.Label
	}{
		{
			desc:         "nil input",
			expectLabels: []telemetry.Label{},
		},
		{
			desc:         "empty input",
			inLabels:     []*hostservices.Label{},
			expectLabels: []telemetry.Label{},
		},
		{
			desc: "one label",
			inLabels: []*hostservices.Label{
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
			inLabels: []*hostservices.Label{
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
			inLabels: []*hostservices.Label{
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
			inLabels: []*hostservices.Label{
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
			outLabels := convertToTelemetryLabels(tt.inLabels)

			assert.Equal(t, tt.expectLabels, outLabels)
		})
	}
}

func TestConvertToRPCLabels(t *testing.T) {
	tests := []struct {
		desc         string
		inLabels     []telemetry.Label
		expectLabels []*hostservices.Label
	}{
		{
			desc:         "nil input",
			expectLabels: []*hostservices.Label{},
		},
		{
			desc:         "empty input",
			inLabels:     []telemetry.Label{},
			expectLabels: []*hostservices.Label{},
		},
		{
			desc: "one label",
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val2",
				},
			},
			expectLabels: []*hostservices.Label{
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
			expectLabels: []*hostservices.Label{
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
			expectLabels: []*hostservices.Label{
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
			outLabels := convertToRPCLabels(tt.inLabels)

			assert.Equal(t, tt.expectLabels, outLabels)
		})
	}
}
