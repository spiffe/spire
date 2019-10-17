package datastore

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartCreateNodeCall return metric
// for server's datastore, on creating a node.
func StartCreateNodeCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.Node, telemetry.Create)
}

// StartDeleteNodeCall return metric
// for server's datastore, on deleting a node.
func StartDeleteNodeCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.Node, telemetry.Delete)
}

// StartFetchNodeCall return metric
// for server's datastore, on fetching a node.
func StartFetchNodeCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.Node, telemetry.Fetch)
}

// StartListNodeCall return metric
// for server's datastore, on listing nodes.
func StartListNodeCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.Node, telemetry.List)
}

// StartGetNodeSelectorsCall return metric
// for server's datastore, on getting selectors for a node.
func StartGetNodeSelectorsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.Node, telemetry.Selectors, telemetry.Fetch)
}

// StartSetNodeSelectorsCall return metric
// for server's datastore, on setting selectors for a node.
func StartSetNodeSelectorsCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.Node, telemetry.Selectors, telemetry.Set)
}

// StartUpdateNodeCall return metric
// for server's datastore, on updating a node.
func StartUpdateNodeCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.Node, telemetry.Update)
}

// End Call Counters
