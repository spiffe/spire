package server

import "github.com/spiffe/spire/pkg/common/telemetry"

// SetEntryDeletedGauge emits a gauge with the number of entries that will
// be deleted in the entry cache.
func SetEntryDeletedGauge(m telemetry.Metrics, deleted int) {
	m.SetGauge([]string{telemetry.Entry, telemetry.Deleted}, float32(deleted))
}

// SetAgentsByIDCacheCountGauge emits a gauge with the number of agents by ID that are
// currently in the node cache.
func SetAgentsByIDCacheCountGauge(m telemetry.Metrics, size int) {
	m.SetGauge([]string{telemetry.Node, telemetry.AgentsByIDCache, telemetry.Count}, float32(size))
}

// SetAgentsByExpiresAtCacheCountGauge emits a gauge with the number of agents by expiresAt that are
// currently in the node cache.
func SetAgentsByExpiresAtCacheCountGauge(m telemetry.Metrics, size int) {
	m.SetGauge([]string{telemetry.Node, telemetry.AgentsByExpiresAtCache, telemetry.Count}, float32(size))
}

// SetSkippedNodeEventIDsCacheCountGauge emits a gauge with the number of entries that are
// currently in the skipped-node events cache.
func SetSkippedNodeEventIDsCacheCountGauge(m telemetry.Metrics, size int) {
	m.SetGauge([]string{telemetry.Node, telemetry.SkippedNodeEventIDs, telemetry.Count}, float32(size))
}

// SetNodeAliasesByEntryIDCacheCountGauge emits a gauge with the number of Node Aliases by EntryID that are
// currently in the entry cache.
func SetNodeAliasesByEntryIDCacheCountGauge(m telemetry.Metrics, size int) {
	m.SetGauge([]string{telemetry.Entry, telemetry.NodeAliasesByEntryIDCache, telemetry.Count}, float32(size))
}

// SetNodeAliasesBySelectorCacheCountGauge emits a gauge with the number of Node Aliases by Selector that are
// currently in the entry cache.
func SetNodeAliasesBySelectorCacheCountGauge(m telemetry.Metrics, size int) {
	m.SetGauge([]string{telemetry.Entry, telemetry.NodeAliasesBySelectorCache, telemetry.Count}, float32(size))
}

// SetEntriesByEntryIDCacheCountGauge emits a gauge with the number of entries by entryID that are
// currently in the entry cache.
func SetEntriesByEntryIDCacheCountGauge(m telemetry.Metrics, size int) {
	m.SetGauge([]string{telemetry.Entry, telemetry.EntriesByEntryIDCache, telemetry.Count}, float32(size))
}

// SetEntriesByParentIDCacheCountGauge emits a gauge with the number of entries by parentID that are
// currently in the entry cache.
func SetEntriesByParentIDCacheCountGauge(m telemetry.Metrics, size int) {
	m.SetGauge([]string{telemetry.Entry, telemetry.EntriesByParentIDCache, telemetry.Count}, float32(size))
}

// SetSkippedEntryEventIDsCacheCountGauge emits a gauge with the number of entries that are
// currently in the skipped-entry events cache.
func SetSkippedEntryEventIDsCacheCountGauge(m telemetry.Metrics, size int) {
	m.SetGauge([]string{telemetry.Entry, telemetry.SkippedEntryEventIDs, telemetry.Count}, float32(size))
}
