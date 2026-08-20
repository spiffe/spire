package adminapi

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

func IncrLoggerAPIConnectionCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.LoggerAPI, telemetry.Connection}, 1)
}

func SetLoggerAPIConnectionGauge(m telemetry.Metrics, connections int32) {
	m.SetGauge([]string{telemetry.LoggerAPI, telemetry.Connections}, float32(connections))
}
