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

// StartGetLatestRegistrationEntryEventIDCall return metric
// for server's datastore, on listing latest registration entry event id.
func StartGetLatestRegistrationEntryEventIDCall(m telemetry.Metrics) *telemetry.CallCounter {
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

// StartGetLatestAttestedNodeEventIDCall return metric
// for server's datastore, on listing attested node event id.
func StartGetLatestAttestedNodeEventIDCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.NodeEvent, telemetry.Fetch)
}
