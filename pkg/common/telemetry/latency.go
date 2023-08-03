package telemetry

import (
	"sync"
	"time"
)

// Latency is used to track timing between two specific events. It
// is a generic version of CallCounter and can be used to measure latency between any two events.
//
// Example:
//
//	func Foo() {
//	    latency := StartLatencyMetric(metrics, "foo")
//	    call.AddLabel("food", "burgers")
//	    // do something
//	    latency.Measure()
//	    // do other things
//	}
//
// Instances of this struct should only be created directly by this package
// and its subpackages, which define the specific metrics that are emitted.
// It is left exported for testing purposes.
type Latency struct {
	metrics Metrics
	key     []string
	labels  []Label
	start   time.Time
	mu      sync.Mutex
}

// StartLatencyMetric starts a "call", which when finished via Done() will emit timing
// and error related metrics.
func StartLatencyMetric(metrics Metrics, key string, keyn ...string) *Latency {
	return &Latency{
		metrics: metrics,
		key:     append([]string{key}, keyn...),
		start:   time.Now(),
	}
}

// AddLabel adds a label to be emitted with the call counter. It is safe to call
// from multiple goroutines.
func (l *Latency) AddLabel(name, value string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.labels = append(l.labels, Label{Name: name, Value: value})
}

// Measure emits a latency metric based on l.start along with labels configured.
func (l *Latency) Measure() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.metrics.MeasureSinceWithLabels(append(l.key, ElapsedTime), l.start, l.labels)
}
