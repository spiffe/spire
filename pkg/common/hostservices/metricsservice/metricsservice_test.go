package metricsservice

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/spiffe/spire/pkg/common/plugin/hostservices"
	"github.com/spiffe/spire/pkg/common/telemetry"
	mock_metrics "github.com/spiffe/spire/test/mock/common/telemetry"
	"github.com/stretchr/testify/assert"
)

func setupMetricsService(metrics telemetry.Metrics) hostservices.MetricsService {
	return New(Config{
		Metrics: metrics,
	})
}

func TestSetGauge(t *testing.T) {
	tests := []struct {
		desc      string
		req       *hostservices.SetGaugeRequest
		expectOut *hostservices.SetGaugeResponse
		expectErr string
	}{
		{
			desc: "no labels",
			req: &hostservices.SetGaugeRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
			expectOut: &hostservices.SetGaugeResponse{},
			expectErr: "",
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
			expectOut: &hostservices.SetGaugeResponse{},
			expectErr: "",
		},
		{
			desc:      "empty request",
			req:       &hostservices.SetGaugeRequest{},
			expectOut: &hostservices.SetGaugeResponse{},
			expectErr: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			convertedLabels := convertToTelemetryLabels(tt.req.Labels)

			mockMetrics := mock_metrics.NewMockMetrics(mockCtrl)
			mockMetrics.EXPECT().SetGaugeWithLabels(tt.req.Key, tt.req.Val, convertedLabels).Return()

			service := setupMetricsService(mockMetrics)
			ret, err := service.SetGauge(context.Background(), tt.req)

			if tt.expectErr != "" {
				assert.EqualError(t, err, tt.expectErr)
				assert.Nil(t, ret)
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expectOut, ret)
		})
	}
}

func TestMeasureSince(t *testing.T) {
	tests := []struct {
		desc      string
		req       *hostservices.MeasureSinceRequest
		expectOut *hostservices.MeasureSinceResponse
		expectErr string
	}{
		{
			desc: "no labels",
			req: &hostservices.MeasureSinceRequest{
				Key:  []string{"key1", "key2"},
				Time: time.Now().Unix(),
			},
			expectOut: &hostservices.MeasureSinceResponse{},
			expectErr: "",
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
			expectOut: &hostservices.MeasureSinceResponse{},
			expectErr: "",
		},
		{
			desc:      "empty request",
			req:       &hostservices.MeasureSinceRequest{},
			expectOut: &hostservices.MeasureSinceResponse{},
			expectErr: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			convertedLabels := convertToTelemetryLabels(tt.req.Labels)

			mockMetrics := mock_metrics.NewMockMetrics(mockCtrl)
			mockMetrics.EXPECT().MeasureSinceWithLabels(tt.req.Key, time.Unix(0, tt.req.Time), convertedLabels).Return()

			service := setupMetricsService(mockMetrics)
			ret, err := service.MeasureSince(context.Background(), tt.req)

			if tt.expectErr != "" {
				assert.EqualError(t, err, tt.expectErr)
				assert.Nil(t, ret)
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expectOut, ret)
		})
	}
}

func TestIncrCounter(t *testing.T) {
	tests := []struct {
		desc      string
		req       *hostservices.IncrCounterRequest
		expectOut *hostservices.IncrCounterResponse
		expectErr string
	}{
		{
			desc: "no labels",
			req: &hostservices.IncrCounterRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
			expectOut: &hostservices.IncrCounterResponse{},
			expectErr: "",
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
			expectOut: &hostservices.IncrCounterResponse{},
			expectErr: "",
		},
		{
			desc:      "empty request",
			req:       &hostservices.IncrCounterRequest{},
			expectOut: &hostservices.IncrCounterResponse{},
			expectErr: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			convertedLabels := convertToTelemetryLabels(tt.req.Labels)

			mockMetrics := mock_metrics.NewMockMetrics(mockCtrl)
			mockMetrics.EXPECT().IncrCounterWithLabels(tt.req.Key, tt.req.Val, convertedLabels).Return()

			service := setupMetricsService(mockMetrics)
			ret, err := service.IncrCounter(context.Background(), tt.req)

			if tt.expectErr != "" {
				assert.EqualError(t, err, tt.expectErr)
				assert.Nil(t, ret)
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expectOut, ret)
		})
	}
}

func TestAddSample(t *testing.T) {
	tests := []struct {
		desc      string
		req       *hostservices.AddSampleRequest
		expectOut *hostservices.AddSampleResponse
		expectErr string
	}{
		{
			desc: "no labels",
			req: &hostservices.AddSampleRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
			expectOut: &hostservices.AddSampleResponse{},
			expectErr: "",
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
			expectOut: &hostservices.AddSampleResponse{},
			expectErr: "",
		},
		{
			desc:      "empty request",
			req:       &hostservices.AddSampleRequest{},
			expectOut: &hostservices.AddSampleResponse{},
			expectErr: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			convertedLabels := convertToTelemetryLabels(tt.req.Labels)

			mockMetrics := mock_metrics.NewMockMetrics(mockCtrl)
			mockMetrics.EXPECT().AddSampleWithLabels(tt.req.Key, tt.req.Val, convertedLabels).Return()

			service := setupMetricsService(mockMetrics)
			ret, err := service.AddSample(context.Background(), tt.req)

			if tt.expectErr != "" {
				assert.EqualError(t, err, tt.expectErr)
				assert.Nil(t, ret)
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expectOut, ret)
		})
	}
}

func TestEmitKey(t *testing.T) {
	tests := []struct {
		desc      string
		req       *hostservices.EmitKeyRequest
		expectOut *hostservices.EmitKeyResponse
		expectErr string
	}{
		{
			desc: "normal request",
			req: &hostservices.EmitKeyRequest{
				Key: []string{"key1", "key2"},
				Val: 0,
			},
			expectOut: &hostservices.EmitKeyResponse{},
			expectErr: "",
		},
		{
			desc:      "empty request",
			req:       &hostservices.EmitKeyRequest{},
			expectOut: &hostservices.EmitKeyResponse{},
			expectErr: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockMetrics := mock_metrics.NewMockMetrics(mockCtrl)
			mockMetrics.EXPECT().EmitKey(tt.req.Key, tt.req.Val).Return()

			service := setupMetricsService(mockMetrics)
			ret, err := service.EmitKey(context.Background(), tt.req)

			if tt.expectErr != "" {
				assert.EqualError(t, err, tt.expectErr)
				assert.Nil(t, ret)
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expectOut, ret)
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
