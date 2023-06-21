package telemetry

import (
	"time"
)

// Blackhole implements the Metrics interface, but throws away the metric data
// Useful for satisfying the Metrics interface when testing code which depends on it.
type Blackhole struct{}

var _ Metrics = Blackhole{}

func (Blackhole) SetGauge([]string, float32)                          {}
func (Blackhole) SetGaugeWithLabels([]string, float32, []Label)       {}
func (Blackhole) EmitKey([]string, float32)                           {}
func (Blackhole) IncrCounter([]string, float32)                       {}
func (Blackhole) IncrCounterWithLabels([]string, float32, []Label)    {}
func (Blackhole) AddSample([]string, float32)                         {}
func (Blackhole) AddSampleWithLabels([]string, float32, []Label)      {}
func (Blackhole) MeasureSince([]string, time.Time)                    {}
func (Blackhole) MeasureSinceWithLabels([]string, time.Time, []Label) {}
