package agent

import "github.com/spiffe/spire/pkg/common/telemetry"

const (
	federatedBundleFresh       = "fresh"
	federatedBundleStale       = "stale"
	federatedBundleExpiry      = "expiry"
	federatedBundleReadmission = "readmission"
)

// InitializeFederatedBundleTransitionCounters registers the transition
// counters at zero so exporters expose both series before the first expiry or
// readmission occurs.
func InitializeFederatedBundleTransitionCounters(m telemetry.Metrics) {
	m.IncrCounter([]string{telemetry.FederatedBundle, federatedBundleExpiry}, 0)
	m.IncrCounter([]string{telemetry.FederatedBundle, federatedBundleReadmission}, 0)
}

// SetFederatedBundleFreshnessCounts records the current number of fresh and
// stale federated bundles held by the agent. Per-remote labels are omitted
// because federation sets can be large and dynamic.
func SetFederatedBundleFreshnessCounts(m telemetry.Metrics, fresh, stale int) {
	m.SetGauge([]string{telemetry.FederatedBundle, federatedBundleFresh}, float32(fresh))
	m.SetGauge([]string{telemetry.FederatedBundle, federatedBundleStale}, float32(stale))
}

// IncrementFederatedBundleExpirations records transitions from fresh to stale.
func IncrementFederatedBundleExpirations(m telemetry.Metrics, count int) {
	if count > 0 {
		m.IncrCounter([]string{telemetry.FederatedBundle, federatedBundleExpiry}, float32(count))
	}
}

// IncrementFederatedBundleReadmissions records stale bundles made visible by a
// later successful server confirmation.
func IncrementFederatedBundleReadmissions(m telemetry.Metrics, count int) {
	if count > 0 {
		m.IncrCounter([]string{telemetry.FederatedBundle, federatedBundleReadmission}, float32(count))
	}
}
