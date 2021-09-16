package datastore

import "github.com/spiffe/spire/pkg/common/telemetry"

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartCreateFederationRelationshipCall return metric
// for server's datastore, on creating a registration.
func StartCreateFederationRelationshipCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.FederationRelationship, telemetry.Create)
}

// StartFetchFederationRelationship return metric
// for server's datastore, on fetching a federation relationship.
func StartFetchFederationRelationshipCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.FederationRelationship, telemetry.Fetch)
}
