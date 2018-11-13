package telemetry

import (
	"io"
	"time"

	"github.com/armon/go-metrics"
)

type Label = metrics.Label
type Sink = metrics.MetricSink

type Metrics interface {
	// A Gauge should retain the last value it is set to
	SetGauge(key []string, val float32)
	SetGaugeWithLabels(key []string, val float32, labels []Label)

	// Should emit a Key/Value pair for each call
	EmitKey(key []string, val float32)

	// Counters should accumulate values
	IncrCounter(key []string, val float32)
	IncrCounterWithLabels(key []string, val float32, labels []Label)

	// Samples are for timing information, where quantiles are used
	AddSample(key []string, val float32)
	AddSampleWithLabels(key []string, val float32, labels []Label)

	// A convenience function for measuring elapsed time with a single line
	MeasureSince(key []string, start time.Time)
	MeasureSinceWithLabels(key []string, start time.Time, labels []Label)
}

type MetricsConfig struct {
	Logger      io.Writer
	ServiceName string
	Sinks       []Sink
}

type MetricsImpl struct {
	*metrics.Metrics

	inmemSignal *metrics.InmemSignal
}

var _ Metrics = (*MetricsImpl)(nil)

// NewMetrics returns a Metric implementation
func NewMetrics(c *MetricsConfig) *MetricsImpl {
	// Always create an in-memory sink
	interval := 1 * time.Second
	retention := 1 * time.Hour
	inmemSink := metrics.NewInmemSink(interval, retention)

	// Allow the in-memory sink to be signaled, printing stats to the log
	inmemSignal := metrics.NewInmemSignal(inmemSink, metrics.DefaultSignal, c.Logger)

	// Although New returns an error type, there is no codepath for non-nil
	// error and the implementation is currently no-fail.
	sinks := metrics.FanoutSink{inmemSink}
	sinks = append(sinks, c.Sinks...)
	m, _ := metrics.New(metrics.DefaultConfig(c.ServiceName), sinks)

	return &MetricsImpl{
		Metrics:     m,
		inmemSignal: inmemSignal,
	}
}

func (t *MetricsImpl) Stop() {
	t.inmemSignal.Stop()
}
