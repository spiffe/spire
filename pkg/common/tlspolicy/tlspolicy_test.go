package tlspolicy

import (
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func mustNewPolicy(t *testing.T, requirePQKEM bool, cfg *TLSConfig) Policy {
	t.Helper()
	p, err := NewPolicy(requirePQKEM, cfg, hclog.NewNullLogger())
	require.NoError(t, err)
	return p
}

func TestParseTLSConfigValid(t *testing.T) {
	ecdheRSA := tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	ecdheECDSA := tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

	tests := []struct {
		name       string
		in         *TLSConfig
		wantMin    uint16
		wantCipher []uint16
		wantCurves []tls.CurveID
	}{
		{
			name:    "nil config",
			in:      nil,
			wantMin: 0,
		},
		{
			name:    "empty config",
			in:      &TLSConfig{},
			wantMin: 0,
		},
		{
			name: "minTLSVersion VersionTLS12 only",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS12",
			},
			wantMin: tls.VersionTLS12,
		},
		{
			name: "minTLSVersion VersionTLS13 only",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS13",
			},
			wantMin: tls.VersionTLS13,
		},
		{
			name: "cipherSuites only",
			in: &TLSConfig{
				CipherSuites: []string{
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				},
			},
			wantMin:    tls.VersionTLS12,
			wantCipher: []uint16{ecdheRSA, ecdheECDSA},
		},
		{
			name: "insecure cipherSuites filtered to Go defaults",
			in: &TLSConfig{
				CipherSuites: []string{"TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
			},
			wantMin: tls.VersionTLS12,
		},
		{
			name: "mixed secure and insecure cipherSuites",
			in: &TLSConfig{
				CipherSuites: []string{
					"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				},
			},
			wantMin:    tls.VersionTLS12,
			wantCipher: []uint16{ecdheRSA},
		},
		{
			name: "cipherSuites ignored when minTLSVersion is VersionTLS13",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS13",
				CipherSuites:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			},
			wantMin: tls.VersionTLS13,
		},
		{
			name: "classical curvePreferences only with default min TLS 1.2",
			in: &TLSConfig{
				CipherSuites:     []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
				CurvePreferences: []string{"X25519", "secp256r1"},
			},
			wantMin:    tls.VersionTLS12,
			wantCipher: []uint16{ecdheRSA},
			wantCurves: []tls.CurveID{tls.X25519, tls.CurveP256},
		},
		{
			name: "classical curvePreferences with explicit TLS 1.2",
			in: &TLSConfig{
				MinTLSVersion:    "VersionTLS12",
				CurvePreferences: []string{"secp384r1", "secp521r1"},
			},
			wantMin:    tls.VersionTLS12,
			wantCurves: []tls.CurveID{tls.CurveP384, tls.CurveP521},
		},
		{
			name: "hybrid and classical curvePreferences with TLS 1.2 min",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS12",
				CurvePreferences: []string{
					"X25519MLKEM768",
					"X25519",
					"secp256r1",
				},
			},
			wantMin: tls.VersionTLS12,
			wantCurves: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.X25519,
				tls.CurveP256,
			},
		},
		{
			name: "hybrid curvePreferences only with TLS 1.3 min",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS13",
				CurvePreferences: []string{
					"X25519MLKEM768",
					"SecP256r1MLKEM768",
					"SecP384r1MLKEM1024",
				},
			},
			wantMin: tls.VersionTLS13,
			wantCurves: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.SecP256r1MLKEM768,
				tls.SecP384r1MLKEM1024,
			},
		},
		{
			name: "TLS 1.3 with classical and hybrid curves",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS13",
				CurvePreferences: []string{
					"X25519MLKEM768",
					"secp256r1",
				},
			},
			wantMin: tls.VersionTLS13,
			wantCurves: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.CurveP256,
			},
		},
		{
			name: "curvePreferences preserve order",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS13",
				CurvePreferences: []string{
					"X25519MLKEM768",
					"X25519",
					"secp256r1",
					"secp384r1",
				},
			},
			wantMin: tls.VersionTLS13,
			wantCurves: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
		},
		{
			name: "curvePreferences decimal ID",
			in: &TLSConfig{
				CurvePreferences: []string{fmt.Sprintf("%d", tls.X25519)},
			},
			wantMin:    tls.VersionTLS12,
			wantCurves: []tls.CurveID{tls.X25519},
		},
		{
			name: "curvePreferences mixed decimal and named",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS13",
				CurvePreferences: []string{
					fmt.Sprintf("%d", tls.X25519MLKEM768),
					"secp256r1",
					fmt.Sprintf("%d", tls.X25519),
				},
			},
			wantMin: tls.VersionTLS13,
			wantCurves: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.CurveP256,
				tls.X25519,
			},
		},
		{
			name: "curvePreferences skip empty and trim whitespace",
			in: &TLSConfig{
				CurvePreferences: []string{"", " X25519 ", " secp256r1"},
			},
			wantMin:    tls.VersionTLS12,
			wantCurves: []tls.CurveID{tls.X25519, tls.CurveP256},
		},
		{
			name: "curvePreferences whitespace only uses Go defaults",
			in: &TLSConfig{
				CurvePreferences: []string{"", " "},
			},
			wantMin: tls.VersionTLS12,
		},
		{
			name: "curve name aliases are case insensitive",
			in: &TLSConfig{
				CurvePreferences: []string{"SECP256R1", "x25519mlkem768"},
				MinTLSVersion:    "VersionTLS13",
			},
			wantMin: tls.VersionTLS13,
			wantCurves: []tls.CurveID{
				tls.CurveP256,
				tls.X25519MLKEM768,
			},
		},
		{
			name: "full TLS 1.2 profile with ciphers and curves",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS12",
				CipherSuites: []string{
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
				},
				CurvePreferences: []string{"X25519", "secp256r1"},
			},
			wantMin:    tls.VersionTLS12,
			wantCipher: []uint16{ecdheRSA, ecdheECDSA},
			wantCurves: []tls.CurveID{tls.X25519, tls.CurveP256},
		},
	}

	logger := hclog.NewNullLogger()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseTLSConfig(tt.in, logger)
			require.NoError(t, err)
			if tt.in == nil || tt.in.empty() {
				require.Nil(t, parsed)
				return
			}
			require.NotNil(t, parsed)
			require.Equal(t, tt.wantMin, parsed.MinTLSVersion)
			require.Equal(t, tt.wantCipher, parsed.CipherSuites)
			require.Equal(t, tt.wantCurves, parsed.CurvePreferences)
		})
	}
}

func TestParseTLSConfigInvalid(t *testing.T) {
	tests := []struct {
		name    string
		in      *TLSConfig
		errPart string
	}{
		{
			name: "unknown minTLSVersion",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS99",
			},
			errPart: "invalid minTLSVersion",
		},
		{
			name: "minTLSVersion below VersionTLS12",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS10",
			},
			errPart: "below the minimum supported version VersionTLS12",
		},
		{
			name: "unknown cipherSuite",
			in: &TLSConfig{
				CipherSuites: []string{"TLS_NOT_A_CIPHER"},
			},
			errPart: "invalid cipherSuites",
		},
		{
			name: "unknown curve name",
			in: &TLSConfig{
				CurvePreferences: []string{"unknown-curve"},
			},
			errPart: "invalid curvePreferences",
		},
		{
			name: "hybrid-only curves with explicit TLS 1.2 min",
			in: &TLSConfig{
				MinTLSVersion:    "VersionTLS12",
				CurvePreferences: []string{"X25519MLKEM768"},
			},
			errPart: "at least one classical curve",
		},
		{
			name: "hybrid-only curves with default TLS 1.2 min",
			in: &TLSConfig{
				CurvePreferences: []string{"X25519MLKEM768"},
			},
			errPart: "at least one classical curve",
		},
		{
			name: "multiple hybrid-only curves with TLS 1.2 min",
			in: &TLSConfig{
				MinTLSVersion: "VersionTLS12",
				CurvePreferences: []string{
					"X25519MLKEM768",
					"SecP256r1MLKEM768",
					"SecP384r1MLKEM1024",
				},
			},
			errPart: "at least one classical curve",
		},
		{
			name: "decimal curve ID out of range",
			in: &TLSConfig{
				CurvePreferences: []string{"999999"},
			},
			errPart: "out of range",
		},
		{
			name: "unsupported decimal curve ID",
			in: &TLSConfig{
				CurvePreferences: []string{"9999"},
			},
			errPart: "not supported",
		},
		{
			name: "duplicate curvePreferences",
			in: &TLSConfig{
				CurvePreferences: []string{"X25519", "X25519"},
			},
			errPart: "duplicate curve preference",
		},
		{
			name: "invalid minTLSVersion prevents later field parsing",
			in: &TLSConfig{
				MinTLSVersion:    "VersionTLS99",
				CurvePreferences: []string{"X25519"},
			},
			errPart: "invalid minTLSVersion",
		},
		{
			name: "invalid cipherSuite prevents curve parsing",
			in: &TLSConfig{
				CipherSuites:     []string{"TLS_NOT_A_CIPHER"},
				CurvePreferences: []string{"X25519"},
			},
			errPart: "invalid cipherSuites",
		},
	}

	logger := hclog.NewNullLogger()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTLSConfig(tt.in, logger)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errPart)
		})
	}
}

func TestParseTLSConfigCurveNameAliases(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want tls.CurveID
	}{
		{"secp256r1", "secp256r1", tls.CurveP256},
		{"secp384r1", "secp384r1", tls.CurveP384},
		{"secp521r1", "secp521r1", tls.CurveP521},
		{"x25519", "X25519", tls.X25519},
		{"x25519mlkem768", "X25519MLKEM768", tls.X25519MLKEM768},
		{"secp256r1mlkem768", "SecP256r1MLKEM768", tls.SecP256r1MLKEM768},
		{"secp384r1mlkem1024", "SecP384r1MLKEM1024", tls.SecP384r1MLKEM1024},
	}

	logger := hclog.NewNullLogger()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			minTLSVersion := ""
			if tt.want == tls.X25519MLKEM768 || tt.want == tls.SecP256r1MLKEM768 || tt.want == tls.SecP384r1MLKEM1024 {
				minTLSVersion = "VersionTLS13"
			}

			parsed, err := ParseTLSConfig(&TLSConfig{
				MinTLSVersion:    minTLSVersion,
				CurvePreferences: []string{tt.in},
			}, logger)
			require.NoError(t, err)
			require.Equal(t, []tls.CurveID{tt.want}, parsed.CurvePreferences)
		})
	}
}

func TestApplyPolicy(t *testing.T) {
	require := require.New(t)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	err := ApplyPolicy(tlsConfig, Policy{})
	require.NoError(err)

	require.Nil(tlsConfig.CipherSuites)
	require.Nil(tlsConfig.CurvePreferences)
	require.Equal(uint16(tls.VersionTLS12), tlsConfig.MinVersion)

	tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, tls.CurveP256,
		},
	}
	err = ApplyPolicy(tlsConfig, Policy{
		RequirePQKEM: true,
	})
	require.NoError(err)

	require.Equal([]tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}, tlsConfig.CurvePreferences)
	require.Equal(uint16(tls.VersionTLS13), tlsConfig.MinVersion)
}

func TestApplyPolicyNilConfig(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	policy, err := NewPolicy(false, nil, hclog.NewNullLogger())
	require.NoError(t, err)
	err = ApplyPolicy(tlsConfig, policy)
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	require.Nil(t, tlsConfig.CipherSuites)
	require.Nil(t, tlsConfig.CurvePreferences)
}

func TestLogPolicyNilConfig(t *testing.T) {
	require.NotPanics(t, func() {
		LogPolicy(Policy{}, hclog.NewNullLogger())
		LogPolicy(Policy{RequirePQKEM: true}, hclog.NewNullLogger())
	})
}

func TestApplyPolicyConfig(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	policy := mustNewPolicy(t, false, &TLSConfig{
		MinTLSVersion: "VersionTLS13",
		CipherSuites:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		CurvePreferences: []string{
			"X25519MLKEM768",
			"secp256r1",
		},
	})
	err := ApplyPolicy(tlsConfig, policy, WithServerTLSConfig())
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	require.Nil(t, tlsConfig.CipherSuites)
	require.Equal(t, []tls.CurveID{tls.X25519MLKEM768, tls.CurveP256}, tlsConfig.CurvePreferences)
}

func TestApplyPolicyConfigPartial(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	policy := mustNewPolicy(t, false, &TLSConfig{MinTLSVersion: "VersionTLS12"})
	err := ApplyPolicy(tlsConfig, policy, WithServerTLSConfig())
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	require.Nil(t, tlsConfig.CipherSuites)
	require.Nil(t, tlsConfig.CurvePreferences)
}

func TestApplyPolicyRequirePQKEMOverridesConfigCurves(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	policy := mustNewPolicy(t, true, &TLSConfig{
		MinTLSVersion:    "VersionTLS12",
		CurvePreferences: []string{"X25519"},
	})
	err := ApplyPolicy(tlsConfig, policy, WithServerTLSConfig())
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	require.Equal(t, []tls.CurveID{
		tls.X25519MLKEM768,
		tls.SecP256r1MLKEM768,
		tls.SecP384r1MLKEM1024,
	}, tlsConfig.CurvePreferences)
}

func TestApplyPolicyConfigSkippedForClient(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	policy := mustNewPolicy(t, false, &TLSConfig{
		MinTLSVersion:    "VersionTLS13",
		CurvePreferences: []string{"X25519"},
	})
	err := ApplyPolicy(tlsConfig, policy)
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	require.Nil(t, tlsConfig.CurvePreferences)
}

func TestApplyPolicyEmptyCipherAndCurveAreNil(t *testing.T) {
	tests := []struct {
		name  string
		cfg   *TLSConfig
		input *tls.Config
	}{
		{
			name:  "nil tls_config policy",
			cfg:   nil,
			input: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		{
			name:  "empty tls_config policy",
			cfg:   &TLSConfig{},
			input: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		{
			name: "min tls version only",
			cfg: &TLSConfig{
				MinTLSVersion: "VersionTLS12",
			},
			input: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		{
			name: "all insecure ciphers filtered",
			cfg: &TLSConfig{
				CipherSuites: []string{"TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
			},
			input: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		{
			name: "whitespace-only curve preferences",
			cfg: &TLSConfig{
				CurvePreferences: []string{"", " "},
			},
			input: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		{
			name: "pre-populated empty slices on input",
			cfg:  nil,
			input: &tls.Config{
				MinVersion:       tls.VersionTLS12,
				CipherSuites:     []uint16{},
				CurvePreferences: []tls.CurveID{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := NewPolicy(false, tt.cfg, hclog.NewNullLogger())
			require.NoError(t, err)

			tlsConfig := tt.input
			err = ApplyPolicy(tlsConfig, policy, WithServerTLSConfig())
			require.NoError(t, err)
			require.Nil(t, tlsConfig.CipherSuites, "CipherSuites must be nil, not an empty slice")
			require.Nil(t, tlsConfig.CurvePreferences, "CurvePreferences must be nil, not an empty slice")
		})
	}
}

func TestNewPolicyReturnsZeroPolicyOnError(t *testing.T) {
	policy, err := NewPolicy(false, &TLSConfig{CurvePreferences: []string{"X25519MLKEM768"}}, hclog.NewNullLogger())
	require.Error(t, err)
	require.False(t, policy.RequirePQKEM)
	require.Nil(t, policy.TLSCfg)
}
