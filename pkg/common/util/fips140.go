package util

import (
	"crypto/fips140"
	"os"
	"strings"
)

// Allows for mocking in tests
var fips140Enabled = fips140.Enabled

// When GODEBUG=fips140=only is used, cryptographic algorithms that are not FIPS 140-3 compliant will return an error or panic
func FIPS140Only() bool {
	return fips140Enabled() && strings.Contains(os.Getenv("GODEBUG"), "fips140=only")
}
