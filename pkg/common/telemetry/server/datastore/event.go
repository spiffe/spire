package datastore

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// StartListRegistrationCall return metric
// for server's datastore, on listing registrations.
func StartListEntryEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.Event, telemetry.List)
}

// StartPruneRegistrationCall return metric
// for server's datastore, on pruning registrations.
func StartPruneEntryEventsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.Event, telemetry.Prune)
}
