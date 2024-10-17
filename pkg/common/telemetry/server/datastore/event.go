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

// StartCreateRegistrationEntryEventForTestingCall return metric
// for server's datastore, on creating a registration entry event.
func StartCreateRegistrationEntryEventForTestingCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.Create)
}

// StartDeleteRegistrationEntryEventForTestingCall return metric
// for server's datastore, on deleting a registration entry event.
func StartDeleteRegistrationEntryEventForTestingCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.Delete)
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

// StartCreateAttestedNodeEventForTestingCall return metric
// for server's datastore, on creating an attested node event.
func StartCreateAttestedNodeEventForTestingCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.Create)
}

// StartDeleteAttestedNodeEventForTestingCall return metric
// for server's datastore, on deleting an attested node event.
func StartDeleteAttestedNodeEventForTestingCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.Delete)
}

// StartFetchAttestedNodeEventCall return metric
// for server's datastore, on fetching an attested node event.
func StartFetchAttestedNodeEventCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.Fetch)
}
