package telemetry

func EmitUptime(m Metrics, v float32) {
	m.SetGauge([]string{"uptime_in_ms"}, v)
}
