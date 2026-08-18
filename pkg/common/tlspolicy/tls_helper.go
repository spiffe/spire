// The TLS parsing helpers in this file mirror k8s.io/component-base/cli/flag
// (TLSVersion, TLSCipherSuites, InsecureTLSCiphers, TLSCurvePreferences, and
// related functions). SPIRE does not import that package directly because
// component-base does not provide compatibility guarantees for its APIs for non k8s workloads.
package tlspolicy

import (
	"crypto/tls"
	"fmt"
	"math"
	"strings"
)

var (
	// ciphers maps strings into tls package cipher constants in
	// https://golang.org/pkg/crypto/tls/#pkg-constants
	ciphers         = map[string]uint16{}
	insecureCiphers = map[string]uint16{}
)

func init() {
	for _, suite := range tls.CipherSuites() {
		ciphers[suite.Name] = suite.ID
	}
	// keep legacy names for backward compatibility
	ciphers["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"] = tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	ciphers["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"] = tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

	for _, suite := range tls.InsecureCipherSuites() {
		insecureCiphers[suite.Name] = suite.ID
	}
}

// InsecureTLSCiphers returns the cipher suites implemented by crypto/tls which have
// security issues.
func InsecureTLSCiphers() map[string]uint16 {
	cipherKeys := make(map[string]uint16, len(insecureCiphers))
	for k, v := range insecureCiphers {
		cipherKeys[k] = v
	}
	return cipherKeys
}

func allCiphers() map[string]uint16 {
	acceptedCiphers := make(map[string]uint16, len(ciphers)+len(insecureCiphers))
	for k, v := range ciphers {
		acceptedCiphers[k] = v
	}
	for k, v := range insecureCiphers {
		acceptedCiphers[k] = v
	}
	return acceptedCiphers
}

// TLSCipherSuites returns a list of cipher suite IDs from the cipher suite names passed.
func TLSCipherSuites(cipherNames []string) ([]uint16, error) {
	if len(cipherNames) == 0 {
		return nil, nil
	}
	ciphersIntSlice := make([]uint16, 0)
	possibleCiphers := allCiphers()
	for _, cipher := range cipherNames {
		intValue, ok := possibleCiphers[cipher]
		if !ok {
			return nil, fmt.Errorf("Cipher suite %s not supported or doesn't exist", cipher)
		}
		ciphersIntSlice = append(ciphersIntSlice, intValue)
	}
	return ciphersIntSlice, nil
}

var versions = map[string]uint16{
	"VersionTLS10": tls.VersionTLS10,
	"VersionTLS11": tls.VersionTLS11,
	"VersionTLS12": tls.VersionTLS12,
	"VersionTLS13": tls.VersionTLS13,
}

// TLSVersion returns the TLS Version ID for the version name passed.
func TLSVersion(versionName string) (uint16, error) {
	if len(versionName) == 0 {
		return DefaultTLSVersion(), nil
	}
	if version, ok := versions[versionName]; ok {
		return version, nil
	}
	return 0, fmt.Errorf("unknown tls version %q", versionName)
}

// DefaultTLSVersion defines the default TLS Version.
func DefaultTLSVersion() uint16 {
	// Can't use SSLv3 because of POODLE and BEAST
	// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
	// Can't use TLSv1.1 because of RC4 cipher usage
	return tls.VersionTLS12
}

// TLSCurvePreferences returns a list of Go's crypto/tls CurveID values from the ids passed.
// The supported values depend on the Go version used.
// See https://pkg.go.dev/crypto/tls#CurveID for values supported for each Go version.
func TLSCurvePreferences(curveIDs []int32) ([]tls.CurveID, error) {
	if len(curveIDs) == 0 {
		return nil, nil
	}
	seen := make(map[int32]bool, len(curveIDs))
	result := make([]tls.CurveID, 0, len(curveIDs))
	for _, id := range curveIDs {
		if id <= 0 || id > math.MaxUint16 {
			return nil, fmt.Errorf("curve preference %d is out of range (must be 1-%d)", id, math.MaxUint16)
		}
		if seen[id] {
			return nil, fmt.Errorf("duplicate curve preference %d", id)
		}
		seen[id] = true
		curve := tls.CurveID(id)
		if strings.HasPrefix(curve.String(), "CurveID(") {
			return nil, fmt.Errorf("curve preference %d is not supported by the current Go version", id)
		}
		result = append(result, curve)
	}
	return result, nil
}
