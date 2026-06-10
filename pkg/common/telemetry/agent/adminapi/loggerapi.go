package adminapi

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// IncrLoggerAPIConnectionCounter indicate Logger
// API connection (some connection is made, running total count)
func IncrLoggerAPIConnectionCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.LoggerAPI, telemetry.Connection}, 1)
}

// SetLoggerAPIConnectionGauge sets the number of active Logger API connections
func SetLoggerAPIConnectionGauge(m telemetry.Metrics, connections int32) {
	m.SetGauge([]string{telemetry.LoggerAPI, telemetry.Connections}, float32(connections))
}
