package workloadapi

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartAttestationCall return metric
// for agent's Workload API Attestor for overall attestation
func StartAttestationCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.WorkloadAPI, telemetry.WorkloadAttestation)
	return cc
}

// StartAttestorCall return metric
// for agent's Workload API Attestor for a specific attestor
func StartAttestorCall(m telemetry.Metrics, aType string) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.WorkloadAPI, telemetry.WorkloadAttestor)
	cc.AddLabel(telemetry.Attestor, aType)
	return cc
}

// End Call Counters

// Counters (literal increments, not call counters)

// IncrConnectionCounter indicate Workload
// API connection (some connection is made, running total count)
func IncrConnectionCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.WorkloadAPI, telemetry.Connection}, 1)
}

// SetConnectionTotalGauge sets the number of active Workload API connections
func SetConnectionTotalGauge(m telemetry.Metrics, connections int32) {
	m.SetGauge([]string{telemetry.WorkloadAPI, telemetry.Connections}, float32(connections))
}

// End Counters

// Add Samples (metric on count of some object, entries, event...)

// AddDiscoveredSelectorsSample count of discovered selectors
// during an agent Workload Attest call
func AddDiscoveredSelectorsSample(m telemetry.Metrics, count float32) {
	m.AddSample([]string{telemetry.WorkloadAPI, telemetry.DiscoveredSelectors}, count)
}

// End Add Samples
