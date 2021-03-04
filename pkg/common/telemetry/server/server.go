package server

import "github.com/spiffe/spire/pkg/common/telemetry"

// SetEntryIgnoredGauge emits a gauge with the number of entries that will
// be ignored in the entry cache.
func SetEntryIgnoredGauge(m telemetry.Metrics, ignored int) {
	m.SetGauge([]string{telemetry.Entry, telemetry.Ignored}, float32(ignored))
}
