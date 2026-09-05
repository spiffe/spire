package brokerapi

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Counters (literal increments, not call counters)

// IncrReferenceResolutionCounter records a workload reference that resolved to
// selectors. mode distinguishes references the agent's own workload attestor
// resolved (telemetry.ResolutionModeAttested) from selectors the broker
// asserted and the agent accepted without attestation
// (telemetry.ResolutionModeAsserted). The asserted path does not run the
// workload attestor, so it is otherwise invisible to the attestation metrics.
//
// The calling broker's SPIFFE ID is deliberately not a label here — it is
// recorded in the audit log instead, to keep SPIFFE IDs out of metric
// cardinality.
func IncrReferenceResolutionCounter(m telemetry.Metrics, referenceType, mode string) {
	m.IncrCounterWithLabels(
		[]string{telemetry.BrokerAPI, telemetry.ReferenceResolution},
		1,
		[]telemetry.Label{
			{Name: telemetry.ReferenceType, Value: referenceType},
			{Name: telemetry.ResolutionMode, Value: mode},
		},
	)
}

// End Counters
