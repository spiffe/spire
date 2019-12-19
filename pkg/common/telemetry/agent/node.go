package agent

import "github.com/spiffe/spire/pkg/common/telemetry"

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartNodeAttestorNewSVIDCall return metric
// for agent node attestor call to get new SVID
// for the agent
func StartNodeAttestorNewSVIDCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Node, telemetry.Attestor, telemetry.NewSVID)
}

// End Call Counters
