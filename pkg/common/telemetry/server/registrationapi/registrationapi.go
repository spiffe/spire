package registrationapi

import "github.com/spiffe/spire/pkg/common/telemetry"

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartCreateEntryCall return metric
// for server's registration API, on creating an entry.
func StartCreateEntryCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.Entry, telemetry.Create)
}

// StartCreateFedBundleCall return metric
// for server's registration API, on creating a federated bundle
func StartCreateFedBundleCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.FederatedBundle, telemetry.Create)
}

// StartCreateJoinTokenCall return metric
// for server's registration API, on creating a join token
func StartCreateJoinTokenCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.JoinToken, telemetry.Create)
}

// StartDeleteEntryCall return metric
// for server's registration API, on deleting an entry
func StartDeleteEntryCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.Entry, telemetry.Delete)
}

// StartDeleteFedBundleCall return metric
// for server's registration API, on deleting a federated bundle
func StartDeleteFedBundleCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.FederatedBundle, telemetry.Delete)
}

// StartFetchBundleCall return metric
// for server's registration API, on fetching a bundle
func StartFetchBundleCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.Bundle, telemetry.Fetch)
}

// StartFetchEntryCall return metric
// for server's registration API, on fetching an entry
func StartFetchEntryCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.Entry, telemetry.Fetch)
}

// StartFetchFedBundleCall return metric
// for server's registration API, on fetching a federated bundle
func StartFetchFedBundleCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.FederatedBundle, telemetry.Fetch)
}

// StartListEntriesCall return metric
// for server's registration API, on listing entries
func StartListEntriesCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.Entry, telemetry.List)
}

// StartListFedBundlesCall return metric
// for server's registration API, on listing federated bundles
func StartListFedBundlesCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.FederatedBundle, telemetry.List)
}

// StartUpdateEntryCall return metric
// for server's registration API, on updating an entry
func StartUpdateEntryCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.Entry, telemetry.Update)
}

// StartUpdateFedBundleCall return metric
// for server's registration API, on updating a federated bundle
func StartUpdateFedBundleCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.RegistrationAPI, telemetry.FederatedBundle, telemetry.Update)
}

// End Call Counters

// Counters (literal increments, not call counters)

// IncrRegistrationAPIUpdatedEntryCounter indicate
// Registration API successfully updating an entry
func IncrRegistrationAPIUpdatedEntryCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.RegistrationAPI, telemetry.Entry, telemetry.Updated}, 1)
}

// End Counters
