package agent

import (
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

const (
	CacheTypeWorkload  = "workload"
	CacheTypeSVIDStore = "svid_store"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartManagerFetchEntriesUpdatesCall returns metric for when agent's
// synchronization manager fetching latest entries information
// from server
func StartManagerFetchEntriesUpdatesCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Manager, telemetry.Sync, telemetry.FetchEntriesUpdates)
}

// StartManagerFetchSVIDsUpdatesCall returns metric for when agent's
// synchronization manager fetching latest SVIDs information
// from server
func StartManagerFetchSVIDsUpdatesCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Manager, telemetry.Sync, telemetry.FetchSVIDsUpdates)
}

// End Call Counters

// Add Samples (metric on count of some object, entries, event...)

// AddCacheManagerExpiredSVIDsSample count of expiring SVIDs according to
// agent cache manager
func AddCacheManagerExpiredSVIDsSample(m telemetry.Metrics, cacheType string, count float32) {
	key := []string{telemetry.CacheManager, telemetry.ExpiringSVIDs}
	if cacheType != "" {
		key = append(key, cacheType)
	}
	m.AddSample(key, count)
}

// AddCacheManagerOutdatedSVIDsSample count of SVIDs with outdated attributes
// according to agent cache manager
func AddCacheManagerOutdatedSVIDsSample(m telemetry.Metrics, cacheType string, count float32) {
	key := []string{telemetry.CacheManager, telemetry.OutdatedSVIDs}
	if cacheType != "" {
		key = append(key, cacheType)
	}
	m.AddSample(key, count)
}

// AddCacheManagerTaintedX509SVIDsSample count of tainted X509-SVIDs according to
// agent cache manager
func AddCacheManagerTaintedX509SVIDsSample(m telemetry.Metrics, cacheType string, count float32) {
	key := []string{telemetry.CacheManager, telemetry.TaintedX509SVIDs}
	if cacheType != "" {
		key = append(key, cacheType)
	}
	m.AddSample(key, count)
}

// AddCacheManagerTaintedJWTSVIDsSample count of tainted JWT-SVIDs according to
// agent cache manager
func AddCacheManagerTaintedJWTSVIDsSample(m telemetry.Metrics, cacheType string, count float32) {
	key := []string{telemetry.CacheManager, telemetry.TaintedJWTSVIDs}
	if cacheType != "" {
		key = append(key, cacheType)
	}
	m.AddSample(key, count)
}

// End Add Samples

func SetSyncStats(m telemetry.Metrics, stats client.SyncStats) {
	m.SetGauge([]string{telemetry.SyncBundlesTotal}, float32(stats.Bundles.Total))
	m.SetGauge([]string{telemetry.SyncEntriesTotal}, float32(stats.Entries.Total))
	m.SetGauge([]string{telemetry.SyncEntriesMissing}, float32(stats.Entries.Missing))
	m.SetGauge([]string{telemetry.SyncEntriesStale}, float32(stats.Entries.Stale))
	m.SetGauge([]string{telemetry.SyncEntriesDropped}, float32(stats.Entries.Dropped))
}
