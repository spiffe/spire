package datastore

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartCreateJoinTokenCall return metric
// for server's datastore, on creating a join token.
func StartCreateJoinTokenCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.JoinToken, telemetry.Create)
}

// StartDeleteJoinTokenCall return metric
// for server's datastore, on deleting a join token.
func StartDeleteJoinTokenCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.JoinToken, telemetry.Delete)
}

// StartFetchJoinTokenCall return metric
// for server's datastore, on fetching a join token.
func StartFetchJoinTokenCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.JoinToken, telemetry.Fetch)
}

// StartPruneJoinTokenCall return metric
// for server's datastore, on pruning join tokens.
func StartPruneJoinTokenCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.JoinToken, telemetry.Prune)
}

// End Call Counters
