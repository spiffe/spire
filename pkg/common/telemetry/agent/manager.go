package agent

import "github.com/spiffe/spire/pkg/common/telemetry"

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartManagerFetchUpdatesCall returns metric for when agent's
// synchronization manager fetching latest SVID information
// from server
func StartManagerFetchUpdatesCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Manager, telemetry.Sync, telemetry.FetchUpdates)
}

// End Call Counters

// Counters (literal increments, not call counters)

// IncrRegistrationEntryCreatedCounter indicate a registration entry is added to agent's cache.
// Takes registration entry SPIFFE ID
func IncrRegistrationEntryCreatedCounter(m telemetry.Metrics, id string) {
	labels := []telemetry.Label{
		{
			Name:  telemetry.SPIFFEID,
			Value: id,
		},
	}
	m.IncrCounterWithLabels([]string{telemetry.CacheManager, telemetry.RegistrationEntry, telemetry.Create}, 1, labels)
}

// IncrRegistrationEntryUpdatedCounter indicate a registration entry is updated in agent's cache.
// Takes registration entry SPIFFE ID
func IncrRegistrationEntryUpdatedCounter(m telemetry.Metrics, id string) {
	labels := []telemetry.Label{
		{
			Name:  telemetry.SPIFFEID,
			Value: id,
		},
	}
	m.IncrCounterWithLabels([]string{telemetry.CacheManager, telemetry.RegistrationEntry, telemetry.Update}, 1, labels)
}

// IncrRegistrationEntryDeletedCounter indicate a registration entry is deleted in agent's cache.
// Takes registration entry SPIFFE ID
func IncrRegistrationEntryDeletedCounter(m telemetry.Metrics, id string) {
	labels := []telemetry.Label{
		{
			Name:  telemetry.SPIFFEID,
			Value: id,
		},
	}
	m.IncrCounterWithLabels([]string{telemetry.CacheManager, telemetry.RegistrationEntry, telemetry.Delete}, 1, labels)
}

// End Counters

// Add Samples (metric on count of some object, entries, event...)

// AddCacheManagerExpiredSVIDsSample count of expiring SVIDs according to
// agent cache manager
func AddCacheManagerExpiredSVIDsSample(m telemetry.Metrics, count float32) {
	m.AddSample([]string{telemetry.CacheManager, telemetry.ExpiringSVIDs}, count)
}

// End Add Samples
