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

// TLSConfig describes TLS configuration settings for terminating endpoints.
// Unset fields are not applied.
type TLSConfig struct {
	CipherSuites     []string `hcl:"cipher_suites"`
	CurvePreferences []string `hcl:"curve_preferences"`
	MinTLSVersion    string   `hcl:"min_tls_version"`
}

// ParsedTLSConfig holds tls_config values parsed once at startup.
type ParsedTLSConfig struct {
	MinTLSVersion    uint16
	CipherSuites     []uint16
	CurvePreferences []tls.CurveID
}

// Policy describes policy options to be applied to a TLS configuration.
//
// A zero-initialised Policy provides reasonable defaults.
type Policy struct {
	// RequirePQKEM determines if a post-quantum-safe KEM should be required for
	// TLS connections. When enabled it takes precedence over TLSConfig curve and
	// minimum version settings.
	RequirePQKEM bool

	// TLSCfg holds parsed tls_config settings. Populated by NewPolicy or ParseTLSConfig.
	TLSCfg *ParsedTLSConfig
}

// ApplyOption selects optional parts of Policy to apply.
type ApplyOption func(*tls.Config, Policy) error

// WithServerTLSConfig applies policy.TLSCfg (min_tls_version, cipher_suites,
// curve_preferences) to the tls.Config.
//
// Intended for terminating TCP listeners only: the server controls what it
// accepts. Outbound clients should negotiate with peers instead; imposing
// these settings on a client can break handshakes with external servers that
// do not support the configured parameters.
func WithServerTLSConfig() ApplyOption {
	return func(cfg *tls.Config, policy Policy) error {
		policy.applyServerTLSConfig(cfg)
		return nil
	}
}

// LogPolicy logs an informational message reporting the configured policy,
// aiding administrators to determine what policy options have been
// successfully enabled.
func LogPolicy(policy Policy, logger hclog.Logger) {
	if policy.RequirePQKEM {
		logger.Debug("Experimental option 'require_pq_kem' is enabled; all TLS connections will require use of a post-quantum safe KEM")
	}
	if policy.TLSCfg == nil {
		logger.Debug("No TLS config configured")
		return
	}
	if policy.TLSCfg.MinTLSVersion != 0 {
		logger.Debug("TLS config min TLS version configured", "min_tls_version", policy.TLSCfg.MinTLSVersion)
	}
	if len(policy.TLSCfg.CipherSuites) > 0 {
		logger.Debug("TLS config cipher suites configured:", "cipher_suites", policy.TLSCfg.CipherSuites)
	}
	if len(policy.TLSCfg.CurvePreferences) > 0 {
		logger.Debug("TLS config curve preferences configured", "curve_preferences", policy.TLSCfg.CurvePreferences)
	}
}

// ApplyPolicy applies policy to config. RequirePQKEM is always honored when
// set. TLSConfig fields are applied only when WithServerTLSConfig() is
// passed. TLSConfig is applied before RequirePQKEM so PQ settings take precedence for backward compatibility.
func ApplyPolicy(config *tls.Config, policy Policy, opts ...ApplyOption) error {
	for _, opt := range opts {
		if err := opt(config, policy); err != nil {
			return err
		}
	}

	if policy.RequirePQKEM {
		applyRequirePQKEM(config)
	}

	return nil
}

func (p Policy) applyServerTLSConfig(cfg *tls.Config) {
	if p.TLSCfg != nil && p.TLSCfg.MinTLSVersion != 0 {
		cfg.MinVersion = p.TLSCfg.MinTLSVersion
	}
	if p.TLSCfg != nil && len(p.TLSCfg.CipherSuites) > 0 {
		cfg.CipherSuites = append([]uint16(nil), p.TLSCfg.CipherSuites...)
	}
	if p.TLSCfg != nil && len(p.TLSCfg.CurvePreferences) > 0 {
		cfg.CurvePreferences = append([]tls.CurveID(nil), p.TLSCfg.CurvePreferences...)
	}
}

func applyRequirePQKEM(config *tls.Config) {
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

// NewPolicy builds a Policy and parses tls_config once at startup.
func NewPolicy(requirePQKEM bool, cfg *TLSConfig) (Policy, error) {
	p := Policy{RequirePQKEM: requirePQKEM}
	if cfg == nil {
		return p, nil
	}

	parsed, err := ParseTLSConfig(cfg)
	if err != nil {
		return p, err
	}

	p.TLSCfg = parsed
	return p, nil
}

// ParseTLSConfig parses tls_config strings into typed TLS settings.
func ParseTLSConfig(cfg *TLSConfig) (*ParsedTLSConfig, error) {
	if cfg == nil || cfg.empty() {
		return nil, nil
	}

	var parsedTLSCfg ParsedTLSConfig

	if cfg.MinTLSVersion != "" {
		minVersion, err := cliflag.TLSVersion(cfg.MinTLSVersion)
		if err != nil {
			return nil, fmt.Errorf("invalid minTLSVersion %q: %w", cfg.MinTLSVersion, err)
		}
		parsedTLSCfg.MinTLSVersion = minVersion
	}

	if len(cfg.CipherSuites) > 0 {
		cipherSuites, err := cliflag.TLSCipherSuites(cfg.CipherSuites)
		if err != nil {
			return nil, fmt.Errorf("invalid cipherSuites: %w", err)
		}
		parsedTLSCfg.CipherSuites = cipherSuites
	}

	if len(cfg.CurvePreferences) > 0 {
		curves, err := parseCurvePreferences(cfg.CurvePreferences)
		if err != nil {
			return nil, fmt.Errorf("invalid curvePreferences: %w", err)
		}
		parsedTLSCfg.CurvePreferences = curves
	}

	return &parsedTLSCfg, nil
}

func (p *TLSConfig) empty() bool {
	return p.MinTLSVersion == "" && len(p.CipherSuites) == 0 && len(p.CurvePreferences) == 0
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
