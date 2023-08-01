package telemetry

import (
	"sync"
	"time"
)

// Latency is used to track timing between two specific events. It
// is a generic version of CallCounter and can be used to measure latency between any two events.
//
// Example 1:
//		func Foo() {
//		    latency := StartLatencyMetric(metrics, "foo")
//		 	call.AddLabel("food", "burgers")
//  		// do something
//	     	latency.Measure() // measure time elapsed between StartLatencyMetric() and Measure()
//			// do other things
//		}
//
// Example 2:
//		func Bar() {
//		    latency := StartLatencyMetric(metrics, "bar")
//		 	call.AddLabel("food", "pizza")
//  		// do something
//	     	latency.MeasureAndReset() // emits metric for time elapsed between StartLatencyMetric() and Measure()
//			// do other things
//          latency.Measure() // emits metric for time elapsed between MeasureAndReset() and Measure()
//		}
//
// Instances of this struct should only be created directly by this package
// and its subpackages, which define the specific metrics that are emitted.
// It is left exported for testing purposes.
type Latency struct {
	metrics Metrics
	key     []string
	labels  []Label
	start   time.Time
	done    bool
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

// Reset resets the start time for the latency metric
func (l *Latency) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.start = time.Now()
}

// Measure emits a latency metric based on l.start along with labels configured.
func (l *Latency) Measure() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.metrics.MeasureSinceWithLabels(append(l.key, ElapsedTime), l.start, l.labels)
}

// MeasureAndReset combines Measure() and Reset()
func (l *Latency) MeasureAndReset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.metrics.MeasureSinceWithLabels(append(l.key, ElapsedTime), l.start, l.labels)
	l.start = time.Now()
}
