package datastore

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// StartFetchRegistrationEntryChangesCall returns metrics for fetching changed
// registration entry IDs.
func StartFetchRegistrationEntryChangesCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.Fetch)
}

// StartFetchAttestedNodeChangesCall returns metrics for fetching changed node
// SPIFFE IDs.
func StartFetchAttestedNodeChangesCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.Fetch)
}

// StartPruneEventsCall returns metrics for pruning datastore events.
func StartPruneEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.Event, telemetry.Prune)
}
