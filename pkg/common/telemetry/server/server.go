package server

import "github.com/spiffe/spire/pkg/common/telemetry"

// SetEntryDeletedGauge emits a gauge with the number of entries that will
// be deleted in the entry cache.
func SetEntryDeletedGauge(m telemetry.Metrics, deleted int) {
	m.SetGauge([]string{telemetry.Entry, telemetry.Deleted}, float32(deleted))
}
