package agent

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartRotateAgentSVIDCall return metric for Agent's SVID
// Rotation.
func StartRotateAgentSVIDCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.AgentSVID, telemetry.Rotate)
	return cc
}

// End Call Counters
