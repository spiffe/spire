package telemetry

import (
	"sync"
)

type LRUMetrics struct {
	metrics Metrics
	mu      sync.Mutex
}

func NewLRUMetrics(c *LRUConfig) *LRUMetrics {
	return &LRUMetrics{
		metrics: c.MetricsImpl,
	}
}

func (c *LRUMetrics) IncrementEntriesAdded(entriesAdded int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics.IncrCounter([]string{EntryAdded}, float32(entriesAdded))
}

func (c *LRUMetrics) IncrementEntriesUpdated(entriesUpdated int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics.IncrCounter([]string{EntryUpdated}, float32(entriesUpdated))
}

func (c *LRUMetrics) IncrementEntriesRemoved(entriesRemoved int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics.IncrCounter([]string{EntryRemoved}, float32(entriesRemoved))
}

func (c *LRUMetrics) SetEntriesMapSize(recordMapSize int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics.SetGauge([]string{RecordMapSize}, float32(recordMapSize))
}

func (c *LRUMetrics) SetSVIDMapSize(svidMapSize int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics.SetGauge([]string{SVIDMapSize}, float32(svidMapSize))
}
