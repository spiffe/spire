package datastore

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// StartListRegistrationEntriesEventsCall return metric
// for server's datastore, on listing registration entry events.
func StartListRegistrationEntriesEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.List)
}

// StartPruneRegistrationEntriesEventsCall return metric
// for server's datastore, on pruning registration entry events.
func StartPruneRegistrationEntriesEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.Prune)
}

// StartCreateRegistrationEntryEventCall return metric
// for server's datastore, on creating a registration entry event.
func StartCreateRegistrationEntryEventCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.Create)
}

// StartDeleteRegistrationEntryEventCall return metric
// for server's datastore, on deleting a registration entry event.
func StartDeleteRegistrationEntryEventCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.Delete)
}

// StartFetchRegistrationEntryEventCall return metric
// for server's datastore, on fetching a registration entry event.
func StartFetchRegistrationEntryEventCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.Fetch)
}

// StartListAttestedNodesEventsCall return metric
// for server's datastore, on listing attested node events.
func StartListAttestedNodesEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.List)
}

// StartPruneAttestedNodesEventsCall return metric
// for server's datastore, on pruning attested node events.
func StartPruneAttestedNodesEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.Prune)
}

// StartCreateAttestedNodeEventCall return metric
// for server's datastore, on creating an attested node event.
func StartCreateAttestedNodeEventCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.Create)
}

// StartDeleteAttestedNodeEventCall return metric
// for server's datastore, on deleting an attested node event.
func StartDeleteAttestedNodeEventCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.Delete)
}

// StartFetchAttestedNodeEventCall return metric
// for server's datastore, on fetching an attested node event.
func StartFetchAttestedNodeEventCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.Fetch)
}
