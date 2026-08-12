package agent

import "github.com/spiffe/spire/pkg/common/telemetry"

func IncrementEntriesAdded(m telemetry.Metrics, entriesAdded int) {
	m.IncrCounter([]string{telemetry.EntryAdded}, float32(entriesAdded))
}

func IncrementEntriesUpdated(m telemetry.Metrics, entriesUpdated int) {
	m.IncrCounter([]string{telemetry.EntryUpdated}, float32(entriesUpdated))
}

func IncrementEntriesRemoved(m telemetry.Metrics, entriesRemoved int) {
	m.IncrCounter([]string{telemetry.EntryRemoved}, float32(entriesRemoved))
}

func SetEntriesMapSize(m telemetry.Metrics, recordMapSize int) {
	m.SetGauge([]string{telemetry.RecordMapSize}, float32(recordMapSize))
}

func SetSVIDMapSize(m telemetry.Metrics, svidType string, svidMapSize int) {
	m.SetGaugeWithLabels([]string{telemetry.SVIDMapSize}, float32(svidMapSize), []telemetry.Label{
		{Name: telemetry.SVIDType, Value: svidType},
	})
}

func SetJWTSVIDCacheSize(m telemetry.Metrics, cacheSize int) {
	m.SetGauge([]string{telemetry.JWTSVIDCacheSize}, float32(cacheSize))
}
