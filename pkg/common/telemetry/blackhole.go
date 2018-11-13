package telemetry

import (
	"time"
)

// Blackhole implements the Metrics interface, but throws away the metric data
// Useful for satisfying the Metrics interface when testing code which depends on it.
type Blackhole struct{}

var _ Metrics = Blackhole{}

func (Blackhole) SetGauge(key []string, val float32)                                   {}
func (Blackhole) SetGaugeWithLabels(key []string, val float32, labels []Label)         {}
func (Blackhole) EmitKey(key []string, val float32)                                    {}
func (Blackhole) IncrCounter(key []string, val float32)                                {}
func (Blackhole) IncrCounterWithLabels(key []string, val float32, labels []Label)      {}
func (Blackhole) AddSample(key []string, val float32)                                  {}
func (Blackhole) AddSampleWithLabels(key []string, val float32, labels []Label)        {}
func (Blackhole) MeasureSince(key []string, start time.Time)                           {}
func (Blackhole) MeasureSinceWithLabels(key []string, start time.Time, labels []Label) {}
