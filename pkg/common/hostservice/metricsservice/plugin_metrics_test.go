package metricsservice

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	metricsv0 "github.com/spiffe/spire/proto/spire/hostservice/common/metrics/v0"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func setupPluginMetricsWrapper(t *testing.T, labels ...telemetry.Label) (telemetry.Metrics, *fakemetrics.FakeMetrics) {
	service, metrics := setupMetricsService()
	server := grpc.NewServer()
	metricsv0.RegisterMetricsServiceServer(server, service)
	socketPath := spiretest.ServeGRPCServerOnTempSocket(t, server)
	conn, err := grpc.DialContext(context.Background(), "unix://"+socketPath, grpc.WithInsecure(), grpc.FailOnNonTempDialError(true))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return WrapPluginMetrics(metricsv0.NewMetricsServiceClient(conn), hclog.NewNullLogger(), labels...), metrics
}

func TestWrapPluginMetricsForContext(t *testing.T) {
	metrics := WrapPluginMetrics(nil, nil, []telemetry.Label{
		{
			Name:  "name1",
			Value: "val1",
		},
		{
			Name:  "name2",
			Value: "val2",
		},
	}...)

	pMetrics, ok := metrics.(pluginMetrics)
	assert.True(t, ok)

	assert.Equal(t, []*metricsv0.Label{
		{
			Name:  "name1",
			Value: "val1",
		},
		{
			Name:  "name2",
			Value: "val2",
		}}, pMetrics.fixedLabels)
}

func TestWrapEmitKey(t *testing.T) {
	tests := []struct {
		desc  string
		inKey []string
		inVal float32
	}{
		{
			desc:  "base call",
			inKey: []string{"key1", "key2"},
			inVal: 3,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.EmitKey(tt.inKey, tt.inVal)

			wrapper, actual := setupPluginMetricsWrapper(t)
			wrapper.EmitKey(tt.inKey, tt.inVal)
			assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
		})
	}
}

func TestWrapSetGaugeWithLabels(t *testing.T) {
	tests := []struct {
		desc        string
		inKey       []string
		inVal       float32
		inLabels    []telemetry.Label
		fixedLabels []telemetry.Label
	}{
		{
			desc:  "no labels",
			inKey: []string{"key1", "key2"},
			inVal: 3,
		},
		{
			desc:  "label",
			inKey: []string{"key1", "key2"},
			inVal: 3,
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val1",
				},
			},
		},
		{
			desc:  "label",
			inKey: []string{"key1", "key2"},
			inVal: 3,
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val1",
				},
			},
			fixedLabels: []telemetry.Label{
				{
					Name:  "constLabel1",
					Value: "constVal1",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.SetGaugeWithLabels(tt.inKey, tt.inVal,
				append(tt.inLabels, tt.fixedLabels...))

			wrapper, actual := setupPluginMetricsWrapper(t, tt.fixedLabels...)
			wrapper.SetGaugeWithLabels(tt.inKey, tt.inVal, tt.inLabels)
			assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
		})
	}
}

func TestWrapIncrCounterWithLabels(t *testing.T) {
	tests := []struct {
		desc        string
		inKey       []string
		inVal       float32
		inLabels    []telemetry.Label
		fixedLabels []telemetry.Label
	}{
		{
			desc:  "no labels",
			inKey: []string{"key1", "key2"},
			inVal: 3,
		},
		{
			desc:  "label",
			inKey: []string{"key1", "key2"},
			inVal: 3,
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val1",
				},
			},
		},
		{
			desc:  "label",
			inKey: []string{"key1", "key2"},
			inVal: 3,
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val1",
				},
			},
			fixedLabels: []telemetry.Label{
				{
					Name:  "constLabel1",
					Value: "constVal1",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.IncrCounterWithLabels(tt.inKey, tt.inVal,
				append(tt.inLabels, tt.fixedLabels...))

			wrapper, actual := setupPluginMetricsWrapper(t, tt.fixedLabels...)
			wrapper.IncrCounterWithLabels(tt.inKey, tt.inVal, tt.inLabels)
			assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
		})
	}
}

func TestWrapAddSampleWithLabels(t *testing.T) {
	tests := []struct {
		desc        string
		inKey       []string
		inVal       float32
		inLabels    []telemetry.Label
		fixedLabels []telemetry.Label
	}{
		{
			desc:  "no labels",
			inKey: []string{"key1", "key2"},
			inVal: 3,
		},
		{
			desc:  "label",
			inKey: []string{"key1", "key2"},
			inVal: 3,
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val1",
				},
			},
		},
		{
			desc:  "label",
			inKey: []string{"key1", "key2"},
			inVal: 3,
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val1",
				},
			},
			fixedLabels: []telemetry.Label{
				{
					Name:  "constLabel1",
					Value: "constVal1",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.AddSampleWithLabels(tt.inKey, tt.inVal,
				append(tt.inLabels, tt.fixedLabels...))

			wrapper, actual := setupPluginMetricsWrapper(t, tt.fixedLabels...)
			wrapper.AddSampleWithLabels(tt.inKey, tt.inVal, tt.inLabels)
			assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
		})
	}
}

func TestWrapMeasureSinceWithLabels(t *testing.T) {
	tests := []struct {
		desc        string
		inKey       []string
		inTime      time.Time
		inLabels    []telemetry.Label
		fixedLabels []telemetry.Label
	}{
		{
			desc:   "no labels",
			inKey:  []string{"key1", "key2"},
			inTime: time.Now(),
		},
		{
			desc:   "label",
			inKey:  []string{"key1", "key2"},
			inTime: time.Now(),
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val1",
				},
			},
		},
		{
			desc:   "label",
			inKey:  []string{"key1", "key2"},
			inTime: time.Now(),
			inLabels: []telemetry.Label{
				{
					Name:  "label1",
					Value: "val1",
				},
			},
			fixedLabels: []telemetry.Label{
				{
					Name:  "constLabel1",
					Value: "constVal1",
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			expected := fakemetrics.New()
			expected.MeasureSinceWithLabels(tt.inKey, tt.inTime,
				append(tt.inLabels, tt.fixedLabels...))

			wrapper, actual := setupPluginMetricsWrapper(t, tt.fixedLabels...)
			wrapper.MeasureSinceWithLabels(tt.inKey, tt.inTime, tt.inLabels)
			assert.Equal(t, expected.AllMetrics(), actual.AllMetrics())
		})
	}
}
