package server

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Counters (literal increments, not call counters)

// IncrBundleManagerUpdateFederatedBundleCounter indicate
// the number of updating federated bundle by bundle manager
func IncrBundleManagerUpdateFederatedBundleCounter(m telemetry.Metrics, trustDomain string) {
	m.IncrCounterWithLabels([]string{
		telemetry.BundleManager,
		telemetry.Update,
		telemetry.FederatedBundle,
	}, 1, []telemetry.Label{
		{Name: telemetry.TrustDomainID, Value: trustDomain},
	})
}

// End Counters

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartBundleManagerFetchFederatedBundleCall return metric for Server's federated bundle fetch.
func StartBundleManagerFetchFederatedBundleCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(
		m,
		telemetry.BundleManager,
		telemetry.Fetch,
		telemetry.FederatedBundle,
	)
}

// End Call Counters
