package agent

import "github.com/spiffe/spire/pkg/common/telemetry"

// Counters (literal increments, not call counters)

// IncrSDSAPIConnectionCounter indicate SDS
// API connection (some connection is made, running total count)
func IncrSDSAPIConnectionCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.SDSAPI, telemetry.Connection}, 1)
}

// DecrSDSAPIConnectionTotalCounter indicate one less
// SDS API active connection (active in that moment)
func DecrSDSAPIConnectionTotalCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.SDSAPI, telemetry.Connections}, -1)
}

// IncrSDSAPIConnectionTotalCounter indicate one more
// SDS API active connections (active in that moment)
func IncrSDSAPIConnectionTotalCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.SDSAPI, telemetry.Connections}, 1)
}

// End Counters
