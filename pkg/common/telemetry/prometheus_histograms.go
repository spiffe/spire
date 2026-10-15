package telemetry

import (
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// prometheusLatencySink forwards every metric to the wrapped go-metrics
// Prometheus sink, which records samples as summaries, and also records each
// latency sample in a histogram named after the sample's key plus histogram.
type prometheusLatencySink struct {
	Sink
	histograms *latencyHistogramCollector
}

func newPrometheusLatencySink(sink Sink, buckets []float64, registerer prometheus.Registerer) (*prometheusLatencySink, error) {
	histograms := &latencyHistogramCollector{buckets: buckets}
	if err := registerer.Register(histograms); err != nil {
		return nil, err
	}
	return &prometheusLatencySink{Sink: sink, histograms: histograms}, nil
}

func (s *prometheusLatencySink) AddSample(key []string, val float32) {
	s.AddSampleWithLabels(key, val, nil)
}

func (s *prometheusLatencySink) AddSampleWithLabels(key []string, val float32, labels []Label) {
	s.Sink.AddSampleWithLabels(key, val, labels)
	if isLatencySample(key) {
		s.histograms.observe(latencyHistogramKey(key), val, labels)
	}
}

// latencyHistogramCollector holds one histogram per metric name and label set.
type latencyHistogramCollector struct {
	buckets    []float64
	histograms sync.Map
}

func (c *latencyHistogramCollector) observe(key []string, val float32, labels []Label) {
	name, id := prometheusNameAndID(key, labels)
	h, ok := c.histograms.Load(id)
	if !ok {
		constLabels := make(prometheus.Labels, len(labels))
		for _, l := range labels {
			constLabels[l.Name] = l.Value
		}
		h, _ = c.histograms.LoadOrStore(id, prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:        name,
			Help:        name,
			ConstLabels: constLabels,
			Buckets:     c.buckets,
		}))
	}
	h.(prometheus.Histogram).Observe(float64(val))
}

// latencyHistogramsDesc is never collected: histograms are created as samples
// arrive, but a collector that describes nothing can't be unregistered.
var latencyHistogramsDesc = prometheus.NewDesc("spire_latency_histograms", "Latency histograms", nil, nil)

func (c *latencyHistogramCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- latencyHistogramsDesc
}

func (c *latencyHistogramCollector) Collect(ch chan<- prometheus.Metric) {
	c.histograms.Range(func(_, h any) bool {
		h.(prometheus.Histogram).Collect(ch)
		return true
	})
}

// prometheusNameReplacer and prometheusNameAndID match the name flattening of
// the go-metrics Prometheus sink, so that a histogram is named like its summary.
var prometheusNameReplacer = strings.NewReplacer(" ", "_", ".", "_", "=", "_", "-", "_", "/", "_")

func prometheusNameAndID(key []string, labels []Label) (string, string) {
	name := prometheusNameReplacer.Replace(strings.Join(key, "_"))

	var id strings.Builder
	id.WriteString(name)
	for _, l := range labels {
		id.WriteString(";" + l.Name + "=" + l.Value)
	}
	return name, id.String()
}
