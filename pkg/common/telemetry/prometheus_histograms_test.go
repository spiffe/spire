package telemetry

import (
	"strings"
	"testing"

	prommetrics "github.com/hashicorp/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPrometheusLatencySink(t *testing.T, buckets []float64) (*prometheusLatencySink, *prometheus.Registry) {
	registry := prometheus.NewRegistry()
	inner, err := prommetrics.NewPrometheusSinkFrom(prommetrics.PrometheusOpts{Registerer: registry})
	require.NoError(t, err)
	sink, err := newPrometheusLatencySink(inner, buckets, registry)
	require.NoError(t, err)
	return sink, registry
}

func gatherFamilies(t *testing.T, registry *prometheus.Registry) map[string]*dto.MetricFamily {
	families, err := registry.Gather()
	require.NoError(t, err)
	out := make(map[string]*dto.MetricFamily, len(families))
	for _, f := range families {
		out[f.GetName()] = f
	}
	return out
}

func TestPrometheusLatencySinkRecordsHistograms(t *testing.T) {
	sink, registry := newTestPrometheusLatencySink(t, []float64{10, 100})
	latencyKey := []string{"spire_agent", "rpc", "workload_api", "fetch_x509svid", ElapsedTime}
	labels := []Label{{Name: "status", Value: "OK"}}

	sink.AddSampleWithLabels(latencyKey, 5, labels)
	sink.AddSampleWithLabels(latencyKey, 50, labels)
	sink.AddSampleWithLabels(latencyKey, 500, labels)
	sink.AddSampleWithLabels(latencyKey, 7, []Label{{Name: "status", Value: "Internal"}})
	sink.AddSample([]string{"spire_agent", "workload_api", "discovered_selectors"}, 3)
	sink.IncrCounter([]string{"spire_agent", "rpc", "workload_api", "fetch_x509svid"}, 1)

	families := gatherFamilies(t, registry)

	assert.Equal(t, dto.MetricType_SUMMARY, families["spire_agent_rpc_workload_api_fetch_x509svid_elapsed_time"].GetType(),
		"the existing summary is still recorded")
	latency := families["spire_agent_rpc_workload_api_fetch_x509svid_elapsed_time_histogram"]
	require.NotNil(t, latency)
	assert.Equal(t, dto.MetricType_HISTOGRAM, latency.GetType())
	require.Len(t, latency.GetMetric(), 2)
	for _, m := range latency.GetMetric() {
		require.Len(t, m.GetLabel(), 1)
		if m.GetLabel()[0].GetValue() != "OK" {
			continue
		}
		h := m.GetHistogram()
		assert.Equal(t, uint64(3), h.GetSampleCount())
		assert.Equal(t, float64(555), h.GetSampleSum())
		require.Len(t, h.GetBucket(), 2)
		assert.Equal(t, float64(10), h.GetBucket()[0].GetUpperBound())
		assert.Equal(t, uint64(1), h.GetBucket()[0].GetCumulativeCount())
		assert.Equal(t, float64(100), h.GetBucket()[1].GetUpperBound())
		assert.Equal(t, uint64(2), h.GetBucket()[1].GetCumulativeCount())
	}

	assert.Equal(t, dto.MetricType_SUMMARY, families["spire_agent_workload_api_discovered_selectors"].GetType())
	assert.NotContains(t, families, "spire_agent_workload_api_discovered_selectors_histogram",
		"samples that are not latencies have no histogram")
	assert.Equal(t, dto.MetricType_COUNTER, families["spire_agent_rpc_workload_api_fetch_x509svid"].GetType())
}

func TestPrometheusLatencyHistogramIsNamedLikeSummary(t *testing.T) {
	key := []string{"spire.agent", "my-api", "a=b", "path/x", "with space", ElapsedTime}
	labels := []Label{{Name: "status", Value: "OK"}}

	summaryRegistry := prometheus.NewRegistry()
	summaries, err := prommetrics.NewPrometheusSinkFrom(prommetrics.PrometheusOpts{Registerer: summaryRegistry})
	require.NoError(t, err)
	summaries.AddSampleWithLabels(key, 1, labels)

	histograms, histogramRegistry := newTestPrometheusLatencySink(t, latencyHistogramBuckets)
	histograms.AddSampleWithLabels(key, 1, labels)

	summaryFamilies := gatherFamilies(t, summaryRegistry)
	require.Len(t, summaryFamilies, 1)
	var summaryName string
	for name := range summaryFamilies {
		summaryName = name
	}

	types := make(map[string]dto.MetricType)
	for name, f := range gatherFamilies(t, histogramRegistry) {
		types[name] = f.GetType()
	}
	assert.Equal(t, map[string]dto.MetricType{
		summaryName:                dto.MetricType_SUMMARY,
		summaryName + "_histogram": dto.MetricType_HISTOGRAM,
	}, types)
}

func TestPrometheusRunnerLatencyHistograms(t *testing.T) {
	config := testPrometheusConfig()
	runner, err := newTestPrometheusRunner(config)
	require.NoError(t, err)
	assert.IsType(t, &prommetrics.PrometheusSink{}, runner.sinks()[0])

	enabled := true
	config.FileConfig.EnableLatencyHistograms = &enabled
	runner, err = newTestPrometheusRunner(config)
	require.NoError(t, err)
	sink, ok := runner.sinks()[0].(*prometheusLatencySink)
	require.True(t, ok)
	assert.Equal(t, latencyHistogramBuckets, sink.histograms.buckets)
}

func TestPrometheusLatencyHistogramsThroughMetrics(t *testing.T) {
	config := testPrometheusConfig()
	disabled, enabled := false, true
	config.ServiceName = "spire_agent"
	config.FileConfig.EnableHostnameLabel = &disabled
	config.FileConfig.EnableLatencyHistograms = &enabled
	metrics, err := NewMetrics(config)
	require.NoError(t, err)
	t.Cleanup(func() {
		sink := metrics.runners[0].(*prometheusRunner).sink.(*prometheusLatencySink)
		prometheus.Unregister(sink.histograms)
		prometheus.Unregister(sink.Sink.(*prommetrics.PrometheusSink))
	})

	StartCall(metrics, "rpc", "fetch").Done(nil)
	metrics.AddSample([]string{"workload_api", "discovered_selectors"}, 2)

	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	types := make(map[string]dto.MetricType)
	for _, f := range families {
		if strings.HasPrefix(f.GetName(), "spire_agent_") {
			types[f.GetName()] = f.GetType()
		}
	}
	assert.Equal(t, map[string]dto.MetricType{
		"spire_agent_rpc_fetch":                         dto.MetricType_COUNTER,
		"spire_agent_rpc_fetch_elapsed_time":            dto.MetricType_SUMMARY,
		"spire_agent_rpc_fetch_elapsed_time_histogram":  dto.MetricType_HISTOGRAM,
		"spire_agent_workload_api_discovered_selectors": dto.MetricType_SUMMARY,
	}, types)
}
