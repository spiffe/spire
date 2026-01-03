package telemetry

func EmitUptime(m Metrics, v float64) {
	m.SetPrecisionGauge([]string{"uptime_in_ms"}, v)
}
