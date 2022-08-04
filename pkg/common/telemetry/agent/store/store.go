package store

import "github.com/spiffe/spire/pkg/common/telemetry"

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartStoreSVIDUpdates return metric for agent's processing and
// StoreSVIDUpdates calls
func StartStoreSVIDUpdates(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.Store, telemetry.StoreSVIDUpdates)
	return cc
}
