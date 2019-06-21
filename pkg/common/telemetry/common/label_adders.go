package common

import (
	"strconv"

	"github.com/spiffe/spire/pkg/common/telemetry"
)

// AddAttestorType add Attestor type label to the given counter
// from the given attestor type
func AddAttestorType(cc *telemetry.CallCounter, aType string) {
	cc.AddLabel(telemetry.Attestor, aType)
}

// AddAudience add the Audience label(s) to the given counter
// from the given audience(s)
func AddAudience(cc *telemetry.CallCounter, auds ...string) {
	for _, aud := range auds {
		cc.AddLabel(telemetry.Audience, aud)
	}
}

// AddCallerID add the CallerID label to the given counter
// from the given ID
func AddCallerID(cc *telemetry.CallCounter, id string) {
	cc.AddLabel(telemetry.CallerID, id)
}

// AddRegistered add the Registered label to the given
// counter, from given boolean
func AddRegistered(cc *telemetry.CallCounter, reg bool) {
	cc.AddLabel(telemetry.Registered, strconv.FormatBool(reg))
}

// AddSPIFFEID add SPIFFE ID label to the given counter
// from the given ID
func AddSPIFFEID(cc *telemetry.CallCounter, id string) {
	cc.AddLabel(telemetry.SPIFFEID, id)
}

// AddRegistrationID add RegistrationID label to the given counter
// from the given ID
func AddRegistrationID(cc *telemetry.CallCounter, id string) {
	cc.AddLabel(telemetry.RegistrationID, id)
}
