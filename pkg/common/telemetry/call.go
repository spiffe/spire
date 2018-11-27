package telemetry

import (
	"sync"
	"time"
)

// CallCounter is used to track timing and other information about a "call". It
// is intended to be scoped to a function with a defer and a named error value,
// if applicable, like so:
//
// func Foo() (err error) {
//     call := StartCall(metrics, "foo")
//     defer call.Done(&err)
//
//     call.AddLabel("food", "burgers")
// }
//
// In the simplest case, if no labels are going to be added, the CountCall function
// provides an easier interface:
//
// func Foo() (err error) {
//     defer CountCall(metrics, "foo")(&err)
// }
type CallCounter struct {
	metrics Metrics
	key     []string
	labels  []Label
	start   time.Time
	done    bool
	mu      sync.Mutex
}

// StartCall starts a "call", which when finished via Done() will emit timing
// and error related metrics.
func StartCall(metrics Metrics, key string, keyn ...string) *CallCounter {
	return &CallCounter{
		metrics: metrics,
		key:     append([]string{key}, keyn...),
		start:   time.Now(),
	}
}

// AddLabel adds a label to be emitted with the call counter. It is safe to call
// from multiple goroutines.
func (c *CallCounter) AddLabel(name, value string) {
	c.mu.Lock()
	c.labels = append(c.labels, Label{Name: name, Value: value})
	c.mu.Unlock()
}

// Done finishes the "call" and emits metrics. No other calls to the CallCounter
// should be done during or after the call to Done. In other words, it is not
// thread-safe and is intended to be the final call to the CallCounter struct.
func (c *CallCounter) Done(errp *error) {
	if c.done {
		return
	}
	c.done = true
	key := c.key
	if errp != nil && *errp != nil {
		key = append(key, "error")
	}
	c.metrics.IncrCounterWithLabels(c.key, 1, c.labels)
	c.metrics.MeasureSince(c.key, c.start)
}

func CountCall(metrics Metrics, key string, keyn ...string) func(*error) {
	counter := StartCall(metrics, key, keyn...)
	return counter.Done
}
