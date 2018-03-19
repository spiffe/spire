package telemetry

import (
	"io"
	"time"

	"github.com/armon/go-metrics"
)

type SinkConfig struct {
	Logger      io.Writer
	ServiceName string

	StopChan <-chan struct{}
}

// sink carries a small bit of state used for cleanup/shutdown, and
// implements the Sink interface.
type sink struct {
	m *metrics.Metrics

	stopChan    <-chan struct{}
	inmemCloser func()
}

// NewSink creates a new sink struct with the appropriate sinks configured.
func NewSink(c *SinkConfig) Sink {
	sinks := metrics.FanoutSink{}

	// Always create an in-memory sink
	interval := 1 * time.Second
	retention := 1 * time.Hour
	inmemSink := metrics.NewInmemSink(interval, retention)
	sinks = append(sinks, inmemSink)

	// Allow the in-memory sink to be signaled, printing stats to the log
	inmemSignal := metrics.NewInmemSignal(inmemSink, metrics.DefaultSignal, c.Logger)

	// Although New returns an error type, there is no codepath for non-nil error.
	config := metrics.DefaultConfig(c.ServiceName)
	m, _ := metrics.New(config, sinks)

	t := &sink{
		m:           m,
		stopChan:    c.StopChan,
		inmemCloser: inmemSignal.Stop,
	}

	go t.cleanup()
	return t
}

func (t *sink) cleanup() {
	<-t.stopChan
	t.inmemCloser()
}

// Satisfy the Sink interface by wrapping metrics.Metric
//
//

func (t *sink) SetGauge(key []string, val float32) {
	t.m.SetGauge(key, val)
}

func (t *sink) SetGaugeWithLabels(key []string, val float32, labels []Label) {
	t.m.SetGaugeWithLabels(key, val, convertLabels(labels))
}

func (t *sink) EmitKey(key []string, val float32) {
	t.m.EmitKey(key, val)
}

func (t *sink) IncrCounter(key []string, val float32) {
	t.m.IncrCounter(key, val)
}

func (t *sink) IncrCounterWithLabels(key []string, val float32, labels []Label) {
	t.m.IncrCounterWithLabels(key, val, convertLabels(labels))
}

func (t *sink) AddSample(key []string, val float32) {
	t.m.AddSample(key, val)
}

func (t *sink) AddSampleWithLabels(key []string, val float32, labels []Label) {
	t.m.AddSampleWithLabels(key, val, convertLabels(labels))
}

func (t *sink) MeasureSince(key []string, start time.Time) {
	t.m.MeasureSince(key, start)
}

func (t *sink) MeasureSinceWithLabels(key []string, start time.Time, labels []Label) {
	t.m.MeasureSinceWithLabels(key, start, convertLabels(labels))
}

func convertLabels(labels []Label) []metrics.Label {
	mLabels := []metrics.Label{}
	for _, l := range labels {
		mLabel := metrics.Label{
			Name:  l.Name,
			Value: l.Value,
		}

		mLabels = append(mLabels, mLabel)
	}

	return mLabels
}
