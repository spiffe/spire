package common

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
	"google.golang.org/grpc/codes"
)

// AddAttestorType add Attestor type label to the given counter
// from the given attestor type
func AddAttestorType(cc *telemetry.CallCounter, aType string) {
	cc.AddLabel(telemetry.Attestor, aType)
}

// AddCallerID add the CallerID label to the given counter
// from the given ID
func AddCallerID(cc *telemetry.CallCounter, id string) {
	cc.AddLabel(telemetry.CallerID, id)
}

// AddErrorClass add Error label to the given counter and
// error code, if the code is not OK
func AddErrorClass(cc *telemetry.CallCounter, code codes.Code) {
	if code != codes.OK {
		cc.AddLabel(telemetry.Error, code.String())
	}
}
