package fakepluginmetrics

import (
	"time"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
)

// FakePluginMetrics mimics behavior of plugin metrics wrapper, delegates
// behavior to FakeMetrics, appending fixed labels
type FakePluginMetrics struct {
	fakeMetrics *fakemetrics.FakeMetrics
	fixedLabels []telemetry.Label
}

// New create new fake metrics wrapper for plugin test
func New(labels ...telemetry.Label) *FakePluginMetrics {
	return &FakePluginMetrics{
		fakeMetrics: fakemetrics.New(),
		fixedLabels: labels,
	}
}

// AllMetrics return all collected metrics
func (m *FakePluginMetrics) AllMetrics() []fakemetrics.MetricItem {
	return m.fakeMetrics.AllMetrics()
}

func (m *FakePluginMetrics) SetGauge(key []string, val float32) {
	m.SetGaugeWithLabels(key, val, []telemetry.Label{})
}

func (m *FakePluginMetrics) SetGaugeWithLabels(key []string, val float32, labels []telemetry.Label) {
	if labels == nil {
		labels = []telemetry.Label{}
	}
	m.fakeMetrics.SetGaugeWithLabels(key, val, append(labels, m.fixedLabels...))
}

func (m *FakePluginMetrics) EmitKey(key []string, val float32) {
	m.fakeMetrics.EmitKey(key, val)
}

func (m *FakePluginMetrics) IncrCounter(key []string, val float32) {
	m.IncrCounterWithLabels(key, val, []telemetry.Label{})
}

func (m *FakePluginMetrics) IncrCounterWithLabels(key []string, val float32, labels []telemetry.Label) {
	if labels == nil {
		labels = []telemetry.Label{}
	}
	m.fakeMetrics.IncrCounterWithLabels(key, val, append(labels, m.fixedLabels...))
}

func (m *FakePluginMetrics) AddSample(key []string, val float32) {
	m.AddSampleWithLabels(key, val, []telemetry.Label{})
}

func (m *FakePluginMetrics) AddSampleWithLabels(key []string, val float32, labels []telemetry.Label) {
	if labels == nil {
		labels = []telemetry.Label{}
	}
	m.fakeMetrics.AddSampleWithLabels(key, val, append(labels, m.fixedLabels...))
}

func (m *FakePluginMetrics) MeasureSince(key []string, start time.Time) {
	m.MeasureSinceWithLabels(key, start, []telemetry.Label{})
}

func (m *FakePluginMetrics) MeasureSinceWithLabels(key []string, start time.Time, labels []telemetry.Label) {
	if labels == nil {
		labels = []telemetry.Label{}
	}
	m.fakeMetrics.MeasureSinceWithLabels(key, start, append(labels, m.fixedLabels...))
}
