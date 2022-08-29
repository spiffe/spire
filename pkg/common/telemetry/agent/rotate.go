package agent

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartRotateAgentSVIDCall return metric for Agent's SVID
// Rotation.
func StartRotateAgentSVIDCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.AgentSVID, telemetry.Rotate)
}

// StartReattestAgentCall return metric for Agent's
// Reattestation.
func StartReattestAgentCall(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Node, telemetry.Attest)
}

// End Call Counters
