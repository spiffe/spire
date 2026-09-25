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
