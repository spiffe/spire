package fakemetrics

import (
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

type MetricType int

const (
	SetGaugeType MetricType = iota
	SetGaugeWithLabelsType
	EmitKeyType
	IncrCounterType
	IncrCounterWithLabelsType
	AddSampleType
	AddSampleWithLabelsType
	MeasureSinceType
	MeasureSinceWithLabelsType
)

type FakeMetrics struct {
	metrics []MetricItem
	mu      *sync.Mutex
	clk     clock.Clock
}

type MetricItem struct {
	Type   MetricType
	Key    []string
	Val    float32
	Labels []telemetry.Label
	Start  time.Time
}

func New(clk clock.Clock) *FakeMetrics {
	return &FakeMetrics{
		mu:  &sync.Mutex{},
		clk: clk,
	}
}

// AllMetrics return all collected metrics
func (m *FakeMetrics) AllMetrics() []MetricItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.metrics
}

func (m *FakeMetrics) SetGauge(key []string, val float32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = append(m.metrics, MetricItem{Type: SetGaugeType, Key: key, Val: val})
}

func (m *FakeMetrics) SetGaugeWithLabels(key []string, val float32, labels []telemetry.Label) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = append(m.metrics, MetricItem{Type: SetGaugeWithLabelsType, Key: key, Val: val, Labels: labels})
}

func (m *FakeMetrics) EmitKey(key []string, val float32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = append(m.metrics, MetricItem{Type: EmitKeyType, Key: key, Val: val})
}

func (m *FakeMetrics) IncrCounter(key []string, val float32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = append(m.metrics, MetricItem{Type: IncrCounterType, Key: key, Val: val})
}

func (m *FakeMetrics) IncrCounterWithLabels(key []string, val float32, labels []telemetry.Label) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = append(m.metrics, MetricItem{Type: IncrCounterWithLabelsType, Key: key, Val: val, Labels: labels})
}

func (m *FakeMetrics) AddSample(key []string, val float32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = append(m.metrics, MetricItem{Type: AddSampleType, Key: key, Val: val})
}

func (m *FakeMetrics) AddSampleWithLabels(key []string, val float32, labels []telemetry.Label) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = append(m.metrics, MetricItem{Type: AddSampleWithLabelsType, Key: key, Val: val, Labels: labels})
}

func (m *FakeMetrics) MeasureSince(key []string, start time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// TODO: refactor MeasureSince to use get start from clock.Clock,
	// for now ignoring provided start and using clock.Now()
	m.metrics = append(m.metrics, MetricItem{Type: MeasureSinceType, Key: key, Start: m.clk.Now()})
}

func (m *FakeMetrics) MeasureSinceWithLabels(key []string, start time.Time, labels []telemetry.Label) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// TODO: refactor MeasureSince to use get start from clock.Clock,
	// for now ignoring provided start and using clock.Now()
	m.metrics = append(m.metrics, MetricItem{Type: MeasureSinceWithLabelsType, Key: key, Start: m.clk.Now(), Labels: labels})
}
