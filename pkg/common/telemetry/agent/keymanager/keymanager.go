package keymanager

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartGenerateKeyPairCall returns a CallCounter for GenerateKeyPair in the Agent KeyManger interface
func StartGenerateKeyPairCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.AgentKeyManager, telemetry.GenerateKeyPair)
	return cc
}

// StartFetchPrivateKeyCall returns a CallCounter for FetchPrivateKey in the Agent KeyManger interface
func StartFetchPrivateKeyCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.AgentKeyManager, telemetry.FetchPrivateKey)
	return cc
}

// StartStorePrivateKeyCall returns a CallCounter for StorePrivateKey in the Agent KeyManger interface
func StartStorePrivateKeyCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.AgentKeyManager, telemetry.StorePrivateKey)
	return cc
}
