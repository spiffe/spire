// Package tlspolicy provides for configuration and enforcement of policies
// relating to TLS.
package tlspolicy

import (
	"crypto/tls"
	"errors"
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
		logger.Debug("TLS config min TLS version configured", "min_tls_version", tls.VersionName(policy.TLSCfg.MinTLSVersion))
	}
	if len(policy.TLSCfg.CipherSuites) > 0 {
		cipherSuites := make([]string, 0, len(policy.TLSCfg.CipherSuites))
		for _, cipherSuite := range policy.TLSCfg.CipherSuites {
			cipherSuites = append(cipherSuites, tls.CipherSuiteName(cipherSuite))
		}
		logger.Debug("TLS config cipher suites configured:", "cipher_suites", cipherSuites)
	}
	if len(policy.TLSCfg.CurvePreferences) > 0 {
		curvePreferences := make([]string, 0, len(policy.TLSCfg.CurvePreferences))
		for _, curvePreference := range policy.TLSCfg.CurvePreferences {
			curvePreferences = append(curvePreferences, curvePreference.String())
		}
		logger.Debug("TLS config curve preferences configured", "curve_preferences", curvePreferences)
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

	logger := hclog.NewNullLogger()

	parsed, err := ParseTLSConfig(cfg, logger)
	if err != nil {
		return p, err
	}

	p.TLSCfg = parsed
	return p, nil
}

// ParseTLSConfig parses tls_config strings into typed TLS settings.
func ParseTLSConfig(cfg *TLSConfig, logger hclog.Logger) (*ParsedTLSConfig, error) {
	if cfg == nil || cfg.empty() {
		return nil, nil
	}

	// Default to TLS 1.2
	parsedTLSCfg := ParsedTLSConfig{MinTLSVersion: uint16(tls.VersionTLS12)}

	if cfg.MinTLSVersion != "" {
		minVersion, err := cliflag.TLSVersion(cfg.MinTLSVersion)
		if err != nil {
			return nil, fmt.Errorf("invalid minTLSVersion %q: %w", cfg.MinTLSVersion, err)
		}
		if minVersion < tls.VersionTLS12 {
			minVersion = tls.VersionTLS12
		}
		parsedTLSCfg.MinTLSVersion = minVersion
	}

	if len(cfg.CipherSuites) > 0 {
		if parsedTLSCfg.MinTLSVersion >= tls.VersionTLS13 {
			logger.Debug("cipherSuites is ignored because minTLSVersion is VersionTLS13 or higher; Go negotiates TLS 1.3 cipher suites automatically")
		} else {
			cipherSuites, err := parseCipherSuites(cfg.CipherSuites, logger)
			if err != nil {
				return nil, fmt.Errorf("invalid cipherSuites: %w", err)
			}
			if len(cipherSuites) == 0 {
				logger.Debug("no supported cipherSuites remain after filtering; Go TLS defaults will be used")
			} else {
				parsedTLSCfg.CipherSuites = cipherSuites
			}
		}
	}

	if len(cfg.CurvePreferences) > 0 {
		curves, err := curvePreferences(cfg.CurvePreferences, parsedTLSCfg.MinTLSVersion, logger)
		if err != nil {
			return nil, fmt.Errorf("invalid curvePreferences: %w", err)
		}
		if len(curves) == 0 {
			logger.Debug("no supported curvePreferences remain after filtering; Go TLS defaults will be used")
		} else {
			parsedTLSCfg.CurvePreferences = curves
		}
	}

	return &parsedTLSCfg, nil
}

func (p *TLSConfig) empty() bool {
	return p.MinTLSVersion == "" && len(p.CipherSuites) == 0 && len(p.CurvePreferences) == 0
}

func parseCipherSuites(names []string, logger hclog.Logger) ([]uint16, error) {
	insecureCiphers := cliflag.InsecureTLSCiphers()
	secureCiphers := make([]string, 0, len(names))
	for _, name := range names {
		if _, ok := insecureCiphers[name]; ok {
			logger.Debug("insecure cipher suite filtered out", "cipher_suite", name)
			continue
		}
		secureCiphers = append(secureCiphers, name)
	}
	return cliflag.TLSCipherSuites(secureCiphers)
}

var wellknownCurveAliases = map[string]int32{
	"curvep256":          int32(tls.CurveP256),
	"p-256":              int32(tls.CurveP256),
	"p256":               int32(tls.CurveP256),
	"secp256r1":          int32(tls.CurveP256),
	"curvep384":          int32(tls.CurveP384),
	"p-384":              int32(tls.CurveP384),
	"p384":               int32(tls.CurveP384),
	"secp384r1":          int32(tls.CurveP384),
	"curvep521":          int32(tls.CurveP521),
	"p-521":              int32(tls.CurveP521),
	"p521":               int32(tls.CurveP521),
	"secp521r1":          int32(tls.CurveP521),
	"x25519":             int32(tls.X25519),
	"x25519mlkem768":     int32(tls.X25519MLKEM768),
	"secp256r1mlkem768":  int32(tls.SecP256r1MLKEM768),
	"secp384r1mlkem1024": int32(tls.SecP384r1MLKEM1024),
}

func curvePreferences(names []string, minVersion uint16, logger hclog.Logger) ([]tls.CurveID, error) {
	givenCurveIDs := make([]int32, 0, len(names))

	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		id, err := curveIDFromName(name)
		if err != nil {
			return nil, err
		}
		givenCurveIDs = append(givenCurveIDs, id)
	}

	curves, err := cliflag.TLSCurvePreferences(givenCurveIDs)
	if err != nil {
		return nil, err
	}

	if minVersion >= tls.VersionTLS13 || len(curves) == 0 {
		return curves, nil
	}

	hasClassicalCurve := false
	for _, curve := range curves {
		if isTLS13OnlyCurve(curve) {
			logger.Debug("TLS 1.2 does not support curve", "curve", curve.String())
			continue
		}
		hasClassicalCurve = true
	}
	if !hasClassicalCurve {
		return nil, errors.New("curvePreferences must include at least one classical curve when minTLSVersion is below VersionTLS13")
	}

	return curves, nil
}

func curveIDFromName(name string) (int32, error) {
	if id, ok := wellknownCurveAliases[strings.ToLower(name)]; ok {
		return id, nil
	}

	id, err := strconv.ParseInt(name, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("unknown curve %q", name)
	}

	return int32(id), nil
}

func isTLS13OnlyCurve(curve tls.CurveID) bool {
	switch curve {
	case tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024:
		return true
	default:
		return false
	}
}
