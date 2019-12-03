package common

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

// AddAttestorType add Attestor type label to the given counter
// from the given attestor type. If type is empty, assign "unknown".
func AddAttestorType(cc *telemetry.CallCounter, aType string) {
	if aType == "" {
		aType = telemetry.Unknown
	}

	cc.AddLabel(telemetry.Attestor, aType)
}

// AddCallerID add the CallerID label to the given counter
// from the given ID. If ID is empty, assign "unknown".
func AddCallerID(cc *telemetry.CallCounter, id string) {
	if id == "" {
		id = telemetry.Unknown
	}

	cc.AddLabel(telemetry.CallerID, id)
}
