package broker

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartFirstX509SVIDUpdateLatency returns Latency metric
// for SubscribeToX509SVID API fetching the first update from cache.
func StartFirstX509SVIDUpdateLatency(m telemetry.Metrics) *telemetry.Latency {
	return telemetry.StartLatencyMetric(m, telemetry.BrokerAPI, telemetry.SubscribeX509SVIDs, telemetry.FirstUpdate)
}

// End Call Counters

// Counters (literal increments, not call counters)

// IncrBrokerAPIConnectionCounter indicate Broker
// API connection (some connection is made, running total count)
func IncrBrokerAPIConnectionCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.BrokerAPI, telemetry.Connection}, 1)
}

// SetBrokerAPIConnectionGauge sets the number of active Broker API connections
func SetBrokerAPIConnectionGauge(m telemetry.Metrics, connections int32) {
	m.SetGauge([]string{telemetry.BrokerAPI, telemetry.Connections}, float32(connections))
}

// End Counters
