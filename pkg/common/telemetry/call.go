package telemetry

import (
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
// Emits latency and counter metrics, including adding a Status label according
// to gRPC code of the given error. If nil error, the code is OK (success).
func (c *CallCounter) Done(errp *error) {
	if c.done {
		return
	}
	c.done = true
	key := c.key

	code := codes.OK
	if errp != nil {
		code = status.Code(*errp)
	}
	c.AddLabel(Status, code.String())

	c.metrics.IncrCounterWithLabels(key, 1, c.labels)
	c.metrics.MeasureSinceWithLabels(append(key, ElapsedTime), c.start, c.labels)
}
