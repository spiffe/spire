package common

import (
	"strconv"

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

// AddRegistered add the Registered label to the given
// counter, from given boolean
func AddRegistered(cc *telemetry.CallCounter, reg bool) {
	cc.AddLabel(telemetry.Registered, strconv.FormatBool(reg))
}

// AddRegistrationID add RegistrationID label to the given counter
// from the given ID
func AddRegistrationID(cc *telemetry.CallCounter, id string) {
	cc.AddLabel(telemetry.RegistrationID, id)
}

// AddSPIFFEID add SPIFFE ID label to the given counter
// from the given ID
func AddSPIFFEID(cc *telemetry.CallCounter, id string) {
	cc.AddLabel(telemetry.SPIFFEID, id)
}

// AddCount add a count label to the given call counter from
// the given count
func AddCount(cc *telemetry.CallCounter, count int) {
	cc.AddLabel(telemetry.Count, strconv.Itoa(count))
}
