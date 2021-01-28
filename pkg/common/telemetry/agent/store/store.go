package store

import "github.com/spiffe/spire/pkg/common/telemetry"

// Call Counters (timing and success metrics) Allows adding labels in-code

//StartPutSVIDCall return metric
// for agent's Put SVIDs calls
func StartPutSVIDCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.Store, telemetry.PutSVID)
	return cc
}

// End Call Counters
