package datastore

import "github.com/spiffe/spire/pkg/common/telemetry"

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartCreateFederationRelationshipCall return metric
// for server's datastore, on creating a registration.
func StartCreateFederationRelationshipCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.FederationRelationship, telemetry.Create)
}

// StartDeleteFederationRelationshipCall return metric
// for server's datastore, on deleting a federation relationship.
func StartDeleteFederationRelationshipCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.FederationRelationship, telemetry.Delete)
}

// StartFetchFederationRelationship return metric
// for server's datastore, on fetching a federation relationship.
func StartFetchFederationRelationshipCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.FederationRelationship, telemetry.Fetch)
}

// StartListFederationRelationshipsCall return metric
// for server's datastore, on listing federation relationships.
func StartListFederationRelationshipsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.FederationRelationship, telemetry.List)
}

// StartUpdateFederationRelationshipCall return metric
// for server's datastore, on updating a federation relationship.
func StartUpdateFederationRelationshipCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.FederationRelationship, telemetry.Update)
}
