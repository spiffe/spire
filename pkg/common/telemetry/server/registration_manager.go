package server

import "github.com/spiffe/spire/pkg/common/telemetry"

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartRegistrationManagerPruneEntryCall returns metric for
// for server registration manager entry pruning
func StartRegistrationManagerPruneEntryCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationEntry, telemetry.Manager, telemetry.Prune)
}

// End Call Counters
