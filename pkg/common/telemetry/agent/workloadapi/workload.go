package workloadapi

import (
	"time"

	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartAttestorCall return metric
// for agent's Workload API Attestor latency for a specific attestor
func StartAttestorLatencyCall(m telemetry.Metrics, aType string) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.WorkloadAPI, telemetry.WorkloadAttestorLatency)
	cc.AddLabel(telemetry.Attestor, aType)
	return cc
}

// StartFetchJWTSVIDCall return metric
// for agent's Workload API, on fetching the workload's JWT SVID
func StartFetchJWTSVIDCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.WorkloadAPI, telemetry.FetchJWTSVID)
	cc.AddLabel(telemetry.SVIDType, telemetry.JWT)
	return cc
}

// StartFetchX509SVIDCall return metric
// for agent's Workload API, on fetching the workload's X509 SVID
func StartFetchX509SVIDCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.WorkloadAPI, telemetry.FetchX509SVID)
	cc.AddLabel(telemetry.SVIDType, telemetry.X509)
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

// IncrFetchJWTBundlesCounter indicate call to Workload
// API, on fetching JWT bundles.
func IncrFetchJWTBundlesCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.WorkloadAPI, telemetry.FetchJWTBundles}, 1)
}

// IncrUpdateJWTBundlesCounter indicate call to Workload
// API, on updating JWT bundles
func IncrUpdateJWTBundlesCounter(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.WorkloadAPI, telemetry.BundlesUpdate, telemetry.JWT}, 1)
}

// IncrValidJWTSVIDCounter indicate call to Workload
// API, on validating JWT SVID. Takes SVID SPIFFE ID and request audience
func IncrValidJWTSVIDCounter(m telemetry.Metrics, id string, aud string) {
	m.IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.ValidateJWTSVID}, 1, []telemetry.Label{
		{
			Name:  telemetry.Subject,
			Value: id,
		},
		{
			Name:  telemetry.Audience,
			Value: aud,
		},
	})
}

// IncrValidJWTSVIDErrCounter indicate call to Workload
// API, on error validating JWT SVID. Takes error string.
func IncrValidJWTSVIDErrCounter(m telemetry.Metrics, err string) {
	m.IncrCounterWithLabels([]string{telemetry.WorkloadAPI, telemetry.ValidateJWTSVID}, 1, []telemetry.Label{
		{
			Name:  telemetry.Error,
			Value: err,
		},
	})
}

// End Counters

// Gauge (remember previous value set)

// SetFetchJWTSVIDTTLGauge set gauge for agent Workload API,
// TTL of fetching JWT SVID for a specific SPIFFE ID
func SetFetchJWTSVIDTTLGauge(m telemetry.Metrics, id string, val float32) {
	m.SetGaugeWithLabels(
		[]string{telemetry.WorkloadAPI, telemetry.FetchJWTSVID, telemetry.TTL},
		val,
		[]telemetry.Label{
			{Name: telemetry.SPIFFEID, Value: id},
		})
}

// SetFetchX509SVIDTTLGauge set gauge for agent Workload API,
// TTL of fetching X509 SVID for a specific SPIFFE ID
func SetFetchX509SVIDTTLGauge(m telemetry.Metrics, id string, val float32) {
	m.SetGaugeWithLabels(
		[]string{telemetry.WorkloadAPI, telemetry.FetchX509SVID, telemetry.TTL},
		val,
		[]telemetry.Label{
			{Name: telemetry.SPIFFEID, Value: id},
		})
}

// End Gauge

// Measure Since (metric on time passed since some given time)

// MeasureAttestDuration emit metric on agent Workload API Attestor latency
// for no specific attestor (the entire attest process)
func MeasureAttestDuration(m telemetry.Metrics, t time.Time) {
	m.MeasureSince([]string{telemetry.WorkloadAPI, telemetry.WorkloadAttestationDuration}, t)
}

// MeasureSendJWTBundleLatency emit metric on agent Workload API,
// latency of sending JWT Bundle to workload
func MeasureSendJWTBundleLatency(m telemetry.Metrics, t time.Time) {
	m.MeasureSince([]string{telemetry.WorkloadAPI, telemetry.SendJWTBundleLatency}, t)
}

// MeasureFetchX509SVIDLatency emit metric on agent Workload API,
// latency of fetching X509SVID
func MeasureFetchX509SVIDLatency(m telemetry.Metrics, t time.Time) {
	m.MeasureSince([]string{telemetry.WorkloadAPI, telemetry.SVIDResponseLatency, telemetry.Fetch}, t)
}

// End Measure Since

// Add Samples (metric on count of some object, entries, event...)

// AddDiscoveredSelectorsSample count of discovered selectors
// during an agent Workload Attest call
func AddDiscoveredSelectorsSample(m telemetry.Metrics, count float32) {
	m.AddSample([]string{telemetry.WorkloadAPI, telemetry.DiscoveredSelectors}, count)
}

// End Add Samples
