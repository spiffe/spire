package adminapi

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Counters (literal increments, not call counters)

// IncrDebugAPIConnectionCounter indicate Debug
// API connection (some connection is made, running total count)
func IncrDebugAPIConnectionCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.DebugAPI, telemetry.Connection}, 1)
}

// SetDebugAPIConnectionGauge sets the number of active Debug API connections
func SetDebugAPIConnectionGauge(m telemetry.Metrics, connections int32) {
	m.SetGauge([]string{telemetry.DebugAPI, telemetry.Connections}, float32(connections))
}

// End Counters
