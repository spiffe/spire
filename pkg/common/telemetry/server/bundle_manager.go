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
