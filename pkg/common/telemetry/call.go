package telemetry

import "time"

type CallCounter struct {
	metrics Metrics
	err     *error
	key     []string
	labels  []Label
	start   time.Time
}

func StartCall(metrics Metrics, err *error, key string, keyn ...string) *CallCounter {
	return &CallCounter{
		metrics: metrics,
		err:     err,
		key:     append([]string{key}, keyn...),
		start:   time.Now(),
	}
}

func (c *CallCounter) AddLabel(name, value string) {
	c.labels = append(c.labels, Label{Name: name, Value: value})
}

func (c *CallCounter) Done() {
	labels := c.labels
	if c.err != nil && *c.err != nil {
		labels = append(labels, Label{Name: "err", Value: (*c.err).Error()})
	}
	c.metrics.IncrCounterWithLabels(c.key, 1, labels)
	c.metrics.MeasureSince(c.key, c.start)
}

func CountCall(metrics Metrics, err *error, key string, keyn ...string) func() {
	counter := StartCall(metrics, err, key, keyn...)
	return counter.Done
}
