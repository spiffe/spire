// Package tlspolicy provides for configuration and enforcement of policies
// relating to TLS.
package tlspolicy

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/hashicorp/go-hclog"
)

// SupportsPQKEM is a constant indicating whether the version of Go used to
// build, and the build configuration, supports a post-quantum safe TLS key
// exchange method.
const SupportsPQKEM = supportsPQKEM

// Post-quantum TLS KEM mode. Determines whether a post-quantum safe KEM should
// be used when establishing a TLS connection.
type PQKEMMode int

const (
	// Do not require use of a post-quantum KEM when establishing a TLS
	// connection. Whether a post-quantum KEM is attempted depends on
	// environmental configuration (e.g. GODEBUG setting tlskyber) and the target
	// Go version at build time.
	PQKEMModeDefault PQKEMMode = iota

	// Attempt use of a post-quantum KEM as the most preferred key exchange
	// method when establishing a TLS connection.
	// Support for this requires Go 1.23 or later.
	// Configuring this will cause connections to fail if support is not available.
	PQKEMModeAttempt

	// Require use of a post-quantum KEM when establishing a TLS connection.
	// Attempts to initiate a connection with a key exchange method which is not
	// post-quantum safe will fail. Support for this requires Go 1.23 or later.
	// Configuring this will cause connections to fail if support is not available.
	PQKEMModeRequire
)

// ParsePQKEMMode parses a string into a PQKEMMode value or returns
// an error.
func ParsePQKEMMode(logger hclog.Logger, value string) (mode PQKEMMode, err error) {
	if value != "" {
		logger.Warn("pq_kem_mode is experimental and may be changed or removed in a future release")
	}

	switch value {
	case "":
		if SupportsPQKEM {
			logger.Debug("pq_kem_mode supported in this build; post-quantum-safe TLS key exchange may or may not be used depending on system configuration")
		} else {
			logger.Debug("pq_kem_mode not supported in this build")
		}
		return PQKEMModeDefault, nil

	case "default":
		if SupportsPQKEM {
			logger.Debug("pq_kem_mode supported and explicitly set to 'default'; post-quantum-safe TLS key exchange may or may not be used depending on system configuration")
		} else {
			logger.Debug("pq_kem_mode explicitly set to 'default'; post-quantum-safe TLS key exchange not supported in this build")
		}
		return PQKEMModeDefault, nil

	case "attempt":
		if !SupportsPQKEM {
			logger.Warn("pq_kem_mode set to 'attempt' but no post-quantum-safe key exchange methods are supported in this build (requires Go 1.23); ignoring")
			return PQKEMModeDefault, nil
		}

		logger.Debug("pq_kem_mode supported and configured in 'attempt' mode")
		return PQKEMModeAttempt, nil

	case "require":
		if !SupportsPQKEM {
			err = errors.New("pq_kem_mode set to 'require' but not supported in this build; requires Go 1.23")
			logger.Error(err.Error())
			return PQKEMModeDefault, err
		}

		logger.Debug("pq_kem_mode supported and configured in 'require' mode - will require post-quantum security for all TLS connections")
		return PQKEMModeRequire, nil

	default:
		return PQKEMModeDefault, fmt.Errorf("pq_kem_mode of %q is invalid; must be one of ['', 'default', 'attempt', 'require']", value)
	}
}

// Policy describes policy options to be applied to a TLS configuration.
//
// A zero-initialised Policy provides reasonable defaults.
type Policy struct {
	// PQKEMMode specifies the post-quantum KEM policy to use.
	PQKEMMode PQKEMMode
}

// Not exported by crypto/tls, so we define it here from the I-D.
const x25519Kyber768Draft00 tls.CurveID = 0x6399

// ApplyPolicy applies the policy options in policy to a given tls.Config,
// which is assumed to have already been obtained from the go-spiffe
// tlsconfig package.
func ApplyPolicy(config *tls.Config, policy Policy) error {
	// Apply post-quantum KEM mode option.
	switch policy.PQKEMMode {
	case PQKEMModeDefault:
		// Nothing to do - allow default curve preferences.

	case PQKEMModeAttempt:
		if len(config.CurvePreferences) == 0 {
			// This is copied from the crypto/tls default curve list.
			config.CurvePreferences = []tls.CurveID{
				x25519Kyber768Draft00,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
			}
		} else if config.CurvePreferences[0] != x25519Kyber768Draft00 {
			// Prepend X25519Kyber768Draft00 to the list, making it most preferred.
			curves := make([]tls.CurveID, 0, len(config.CurvePreferences)+1)
			curves = append(curves, x25519Kyber768Draft00)
			curves = append(curves, config.CurvePreferences...)
			config.CurvePreferences = curves
		}

	case PQKEMModeRequire:
		// List only known PQ-safe KEMs as valid curves.
		config.CurvePreferences = []tls.CurveID{
			x25519Kyber768Draft00,
		}

		// Require TLS 1.3, as all PQ-safe KEMs require it anyway.
		if config.MinVersion < tls.VersionTLS13 {
			config.MinVersion = tls.VersionTLS13
		}
	}

	return nil
}
