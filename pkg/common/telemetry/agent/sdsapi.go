package agent

import "github.com/spiffe/spire/pkg/common/telemetry"

// Counters (literal increments, not call counters)

// IncrSDSAPIConnectionCounter indicate SDS
// API connection (some connection is made, running total count)
func IncrSDSAPIConnectionCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.SDSAPI, telemetry.Connection}, 1)
}

// SetSDSAPIConnectionTotalGauge sets the number of active SDS connections
func SetSDSAPIConnectionTotalGauge(m telemetry.Metrics, connections int32) {
	m.IncrCounter([]string{telemetry.SDSAPI, telemetry.Connections}, float32(connections))
}

// End Counters
