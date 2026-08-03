// Package tlspolicy provides for configuration and enforcement of policies
// relating to TLS.
package tlspolicy

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
	cliflag "k8s.io/component-base/cli/flag"
)

// TLSProfile describes TLS profile settings for terminating endpoints.
// Unset fields are not applied.
type TLSProfile struct {
	MinTLSVersion    string   `hcl:"min_tls_version"`
	CipherSuites     []string `hcl:"cipher_suites"`
	CurvePreferences []string `hcl:"curve_preferences"`
}

// Policy describes policy options to be applied to a TLS configuration.
//
// A zero-initialised Policy provides reasonable defaults.
type Policy struct {
	// RequirePQKEM determines if a post-quantum-safe KEM should be required for
	// TLS connections. When enabled it takes precedence over Profile curve and
	// minimum version settings.
	RequirePQKEM bool

	Profile *TLSProfile
}

// LogPolicy logs an informational message reporting the configured policy,
// aiding administrators to determine what policy options have been
// successfully enabled.
func LogPolicy(policy Policy, logger hclog.Logger) {
	if policy.RequirePQKEM {
		logger.Debug("Experimental option 'require_pq_kem' is enabled; all TLS connections will require use of a post-quantum safe KEM")
	}
	if policy.Profile == nil {
		logger.Debug("No TLS profile configured")
		return
	}
	if policy.Profile.MinTLSVersion != "" {
		logger.Debug("TLS profile min TLS version configured", "min_tls_version", policy.Profile.MinTLSVersion)
	}
	if len(policy.Profile.CipherSuites) > 0 {
		logger.Debug("TLS profile cipher suites configured", "count", len(policy.Profile.CipherSuites))
	}
	if len(policy.Profile.CurvePreferences) > 0 {
		logger.Debug("TLS profile curve preferences configured", "count", len(policy.Profile.CurvePreferences))
	}
}

// ApplyPolicy applies the require_pq_kem and TLSProfile, if provided.
// TLSProfile is applied only when isTCPListener is true, i.e. for
// terminating TLS endpoints (listeners).
func ApplyPolicy(config *tls.Config, policy Policy, isTCPListener bool) error {
	if isTCPListener {
		if err := applyProfile(config, policy.Profile); err != nil {
			return err
		}
	}

	if policy.RequirePQKEM {
		// List only known PQ-safe KEMs as valid curves.
		config.CurvePreferences = []tls.CurveID{
			tls.X25519MLKEM768,
			tls.SecP256r1MLKEM768,
			tls.SecP384r1MLKEM1024,
		}

		// Require TLS 1.3, as all PQ-safe KEMs require it anyway.
		if config.MinVersion < tls.VersionTLS13 {
			config.MinVersion = tls.VersionTLS13
		}
	}

	return nil
}

func (p *TLSProfile) empty() bool {
	return p.MinTLSVersion == "" && len(p.CipherSuites) == 0 && len(p.CurvePreferences) == 0
}

func applyProfile(cfg *tls.Config, profile *TLSProfile) error {
	if profile == nil || profile.empty() {
		return nil
	}

	if profile.MinTLSVersion != "" {
		minVersion, err := cliflag.TLSVersion(profile.MinTLSVersion)
		if err != nil {
			return fmt.Errorf("invalid minTLSVersion %q: %w", profile.MinTLSVersion, err)
		}
		cfg.MinVersion = minVersion
	}

	if len(profile.CipherSuites) > 0 {
		cipherSuites, err := cliflag.TLSCipherSuites(profile.CipherSuites)
		if err != nil {
			return fmt.Errorf("invalid cipherSuites: %w", err)
		}
		cfg.CipherSuites = cipherSuites
	}

	if len(profile.CurvePreferences) > 0 {
		curves, err := parseCurvePreferences(profile.CurvePreferences)
		if err != nil {
			return fmt.Errorf("invalid curvePreferences: %w", err)
		}
		cfg.CurvePreferences = curves
	}

	return nil
}

func parseCurvePreferences(names []string) ([]tls.CurveID, error) {
	curves := make([]tls.CurveID, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		if isDecimal(name) {
			id, err := strconv.ParseUint(name, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid curve ID %q: %w", name, err)
			}
			curves = append(curves, tls.CurveID(id))
			continue
		}

		switch strings.ToLower(name) {
		case "curvep256", "p-256", "p256", "secp256r1":
			curves = append(curves, tls.CurveP256)
		case "curvep384", "p-384", "p384", "secp384r1":
			curves = append(curves, tls.CurveP384)
		case "curvep521", "p-521", "p521", "secp521r1":
			curves = append(curves, tls.CurveP521)
		case "x25519":
			curves = append(curves, tls.X25519)
		case "x25519mlkem768":
			curves = append(curves, tls.X25519MLKEM768)
		case "secp256r1mlkem768":
			curves = append(curves, tls.SecP256r1MLKEM768)
		case "secp384r1mlkem1024":
			curves = append(curves, tls.SecP384r1MLKEM1024)
		default:
			return nil, fmt.Errorf("unknown curve %q", name)
		}
	}

	return curves, nil
}

func isDecimal(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
