package telemetry

func EmitUptime(m Metrics, v float32) {
	m.SetGauge([]string{"uptime"}, v)
}
