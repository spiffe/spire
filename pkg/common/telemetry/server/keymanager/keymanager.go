package keymanager

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// Call Counters (timing and success metrics)
// Allows adding labels in-code

// StartGenerateKeyCall returns a CallCounter for GenerateKeyPair in the Server KeyManager interface
func StartGenerateKeyCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.ServerKeyManager, telemetry.GenerateKey)
	return cc
}

// StartGetPublicKeyCall returns a CallCounter for GetPublicKey in the Server KeyManager interface
func StartGetPublicKeyCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.ServerKeyManager, telemetry.GetPublicKey)
	return cc
}

// StartGetPublicKeysCall returns a CallCounter for GetPublicKeys in the Server KeyManager interface
func StartGetPublicKeysCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.ServerKeyManager, telemetry.GetPublicKeys)
	return cc
}

// StartSignDataCall returns a CallCounter for SignData in the Server KeyManager interface
func StartSignDataCall(m telemetry.Metrics) *telemetry.CallCounter {
	cc := telemetry.StartCall(m, telemetry.ServerKeyManager, telemetry.SignData)
	return cc
}
