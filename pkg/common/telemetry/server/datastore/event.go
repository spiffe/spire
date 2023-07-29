package datastore

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// StartListRegistrationCall return metric
// for server's datastore, on listing registrations.
func StartListRegistrationEntriesEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.List)
}

// StartPruneRegistrationCall return metric
// for server's datastore, on pruning registrations.
func StartPruneRegistrationEntriesEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.RegistrationEntryEvent, telemetry.Prune)
}
