package common

import (
	"strings"

	"github.com/spiffe/spire/pkg/common/telemetry"
)

// SanitizeLabel take the input string and replace all `.`'s with
// `_`'s.
func SanitizeLabel(val string) string {
	return strings.ReplaceAll(val, ".", "_")
}

// GetSanitizedLabel take the input name and value, sanitize the
// value, and return the resulting telemetry label.
func GetSanitizedLabel(name, val string) telemetry.Label {
	return telemetry.Label{
		Name:  name,
		Value: SanitizeLabel(val),
	}
}
