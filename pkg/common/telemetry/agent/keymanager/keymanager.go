package keymanager

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartGenerateKeyPairCall returns a CallCounter for GenerateKeyPair in the Agent KeyManager interface
func StartGenerateKeyPairCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.AgentKeyManager, telemetry.GenerateKeyPair)
	return cc
}

// StartFetchPrivateKeyCall returns a CallCounter for FetchPrivateKey in the Agent KeyManager interface
func StartFetchPrivateKeyCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.AgentKeyManager, telemetry.FetchPrivateKey)
	return cc
}

// StartStorePrivateKeyCall returns a CallCounter for StorePrivateKey in the Agent KeyManager interface
func StartStorePrivateKeyCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.AgentKeyManager, telemetry.StorePrivateKey)
	return cc
}

// StartGenerateKeyCall returns a CallCounter for GenerateKey in the Agent KeyManager interface
func StartGenerateKeyCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.AgentKeyManager, telemetry.GenerateKey)
	return cc
}

// StartGetKeyCall returns a CallCounter for GetKey in the Agent KeyManager interface
func StartGetKeyCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.AgentKeyManager, telemetry.GetKey)
	return cc
}

// StartGetKeysCall returns a CallCounter for GetKeys in the Agent KeyManager interface
func StartGetKeysCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.AgentKeyManager, telemetry.GetKeys)
	return cc
}
