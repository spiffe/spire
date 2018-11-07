package telemetry

import "time"

type withLabels struct {
	sink   Sink
	labels []Label
}

func WithLabels(sink Sink, labels []Label) Sink {
	if len(labels) == 0 {
		return sink
	}
	return &withLabels{
		sink:   sink,
		labels: labels,
	}
}

func (w *withLabels) SetGauge(key []string, val float32) {
	w.sink.SetGaugeWithLabels(key, val, w.labels)
}

func (w *withLabels) SetGaugeWithLabels(key []string, val float32, labels []Label) {
	w.sink.SetGaugeWithLabels(key, val, w.combineLabels(labels))
}

func (w *withLabels) EmitKey(key []string, val float32) {
	w.sink.EmitKey(key, val)
}

func (w *withLabels) IncrCounter(key []string, val float32) {
	w.sink.IncrCounterWithLabels(key, val, w.labels)
}

func (w *withLabels) IncrCounterWithLabels(key []string, val float32, labels []Label) {
	w.sink.IncrCounterWithLabels(key, val, w.combineLabels(labels))
}

func (w *withLabels) AddSample(key []string, val float32) {
	w.sink.AddSampleWithLabels(key, val, w.labels)
}

func (w *withLabels) AddSampleWithLabels(key []string, val float32, labels []Label) {
	w.sink.AddSampleWithLabels(key, val, w.combineLabels(labels))
}

func (w *withLabels) MeasureSince(key []string, start time.Time) {
	w.sink.MeasureSinceWithLabels(key, start, w.labels)
}

func (w *withLabels) MeasureSinceWithLabels(key []string, start time.Time, labels []Label) {
	w.sink.MeasureSinceWithLabels(key, start, w.combineLabels(labels))
}

func (w *withLabels) combineLabels(labels []Label) (combined []Label) {
	combined = append(combined, w.labels...)
	combined = append(combined, labels...)
	return combined
}
