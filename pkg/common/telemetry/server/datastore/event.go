package datastore

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// StartListRegistrationEntryEventsCall return metric
// for server's datastore, on listing registration entry events.
func StartListRegistrationEntryEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.List)
}

// StartPruneRegistrationEntryEventsCall return metric
// for server's datastore, on pruning registration entry events.
func StartPruneRegistrationEntryEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.Prune)
}

// StartFetchRegistrationEntryEventCall return metric
// for server's datastore, on fetching a registration entry event.
func StartFetchRegistrationEntryEventCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.Fetch)
}

// StartListAttestedNodeEventsCall return metric
// for server's datastore, on listing attested node events.
func StartListAttestedNodeEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.List)
}

// StartPruneAttestedNodeEventsCall return metric
// for server's datastore, on pruning attested node events.
func StartPruneAttestedNodeEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.Prune)
}

// StartFetchAttestedNodeEventCall return metric
// for server's datastore, on fetching an attested node event.
func StartFetchAttestedNodeEventCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.Fetch)
}
