package agent

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/telemetry/common"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartRotateAgentSVIDCall return metric for Agent's SVID
// Rotation. Takes the agent's spiffe ID as a label.
func StartRotateAgentSVIDCall(m telemetry.Metrics, id string) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.AgentSVID, telemetry.Rotate)
	common.AddSPIFFEID(cc, id)
	return cc
}

// End Call Counters
