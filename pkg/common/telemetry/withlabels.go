package telemetry

import "time"

type withLabels struct {
	metrics Metrics
	labels  []Label
}

var _ Metrics = (*withLabels)(nil)

func WithLabels(metrics Metrics, labels []Label) Metrics {
	if len(labels) == 0 {
		return metrics
	}
	return &withLabels{
		metrics: metrics,
		labels:  labels,
	}
}

func (w *withLabels) SetGauge(key []string, val float32) {
	w.metrics.SetGaugeWithLabels(key, val, w.labels)
}

func (w *withLabels) SetGaugeWithLabels(key []string, val float32, labels []Label) {
	w.metrics.SetGaugeWithLabels(key, val, w.combineLabels(labels))
}

func (w *withLabels) EmitKey(key []string, val float32) {
	w.metrics.EmitKey(key, val)
}

func (w *withLabels) IncrCounter(key []string, val float32) {
	w.metrics.IncrCounterWithLabels(key, val, w.labels)
}

func (w *withLabels) IncrCounterWithLabels(key []string, val float32, labels []Label) {
	w.metrics.IncrCounterWithLabels(key, val, w.combineLabels(labels))
}

func (w *withLabels) AddSample(key []string, val float32) {
	w.metrics.AddSampleWithLabels(key, val, w.labels)
}

func (w *withLabels) AddSampleWithLabels(key []string, val float32, labels []Label) {
	w.metrics.AddSampleWithLabels(key, val, w.combineLabels(labels))
}

func (w *withLabels) MeasureSince(key []string, start time.Time) {
	w.metrics.MeasureSinceWithLabels(key, start, w.labels)
}

func (w *withLabels) MeasureSinceWithLabels(key []string, start time.Time, labels []Label) {
	w.metrics.MeasureSinceWithLabels(key, start, w.combineLabels(labels))
}

func (w *withLabels) combineLabels(labels []Label) (combined []Label) {
	combined = append(combined, w.labels...)
	combined = append(combined, labels...)
	return combined
}
