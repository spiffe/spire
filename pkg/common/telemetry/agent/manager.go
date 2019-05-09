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

// Add Samples (metric on count of some object, entries, event...)

// AddCacheManagerExpiredSVIDsSample count of expiring SVIDs according to
// agent cache manager
func AddCacheManagerExpiredSVIDsSample(m telemetry.Metrics, count float32) {
	m.AddSample([]string{telemetry.CacheManager, telemetry.ExpiringSVIDs}, count)
}

// End Add Samples
