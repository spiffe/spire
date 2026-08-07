package tlspolicy

import (
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestApplyPolicy(t *testing.T) {
	require := require.New(t)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	err := ApplyPolicy(tlsConfig, Policy{})
	require.NoError(err)

	require.Equal(0, len(tlsConfig.CurvePreferences))
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
	err := ApplyPolicy(tlsConfig, Policy{TLSCfg: nil})
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	require.Empty(t, tlsConfig.CipherSuites)
	require.Empty(t, tlsConfig.CurvePreferences)
}

func TestLogPolicyNilConfig(t *testing.T) {
	require.NotPanics(t, func() {
		LogPolicy(Policy{}, hclog.NewNullLogger())
		LogPolicy(Policy{RequirePQKEM: true}, hclog.NewNullLogger())
	})
}

func TestApplyPolicyConfig(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	err := ApplyPolicy(tlsConfig, Policy{
		TLSCfg: &TLSConfig{
			MinTLSVersion: "VersionTLS13",
			CipherSuites:  []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			CurvePreferences: []string{
				"X25519MLKEM768",
				"secp256r1",
			},
		},
	}, WithServerTLSConfig())
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	require.NotEmpty(t, tlsConfig.CipherSuites)
	require.Equal(t, []tls.CurveID{tls.X25519MLKEM768, tls.CurveP256}, tlsConfig.CurvePreferences)
}

func TestApplyPolicyConfigPartial(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	err := ApplyPolicy(tlsConfig, Policy{
		TLSCfg: &TLSConfig{MinTLSVersion: "VersionTLS12"},
	}, WithServerTLSConfig())
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	require.Empty(t, tlsConfig.CipherSuites)
	require.Empty(t, tlsConfig.CurvePreferences)
}

func TestApplyPolicyRequirePQKEMOverridesConfigCurves(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	err := ApplyPolicy(tlsConfig, Policy{
		RequirePQKEM: true,
		TLSCfg: &TLSConfig{
			MinTLSVersion:    "VersionTLS12",
			CurvePreferences: []string{"X25519"},
		},
	}, WithServerTLSConfig())
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
	err := ApplyPolicy(tlsConfig, Policy{
		TLSCfg: &TLSConfig{
			MinTLSVersion:    "VersionTLS13",
			CurvePreferences: []string{"X25519"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	require.Empty(t, tlsConfig.CurvePreferences)
}

func TestApplyPolicyInvalidMinTLSVersion(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	err := ApplyPolicy(tlsConfig, Policy{
		TLSCfg: &TLSConfig{MinTLSVersion: "VersionTLS99"},
	}, WithServerTLSConfig())
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid minTLSVersion")
}

func TestApplyPolicyInvalidCipherSuite(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	err := ApplyPolicy(tlsConfig, Policy{
		TLSCfg: &TLSConfig{CipherSuites: []string{"TLS_NOT_A_CIPHER"}},
	}, WithServerTLSConfig())
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid cipherSuites")
}

func TestApplyPolicyInvalidCurve(t *testing.T) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	err := ApplyPolicy(tlsConfig, Policy{
		TLSCfg: &TLSConfig{CurvePreferences: []string{"unknown-curve"}},
	}, WithServerTLSConfig())
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid curvePreferences")
}

func TestParseCurvePreferences(t *testing.T) {
	tests := []struct {
		input string
		want  tls.CurveID
	}{
		{"CurveP256", tls.CurveP256},
		{"P256", tls.CurveP256},
		{"P-256", tls.CurveP256},
		{"secp256r1", tls.CurveP256},
		{"X25519", tls.X25519},
		{"X25519MLKEM768", tls.X25519MLKEM768},
		{"SecP256r1MLKEM768", tls.SecP256r1MLKEM768},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			curves, err := parseCurvePreferences([]string{tt.input})
			require.NoError(t, err)
			require.Equal(t, []tls.CurveID{tt.want}, curves)
		})
	}
}

func TestParseCurvePreferencesDecimalID(t *testing.T) {
	curves, err := parseCurvePreferences([]string{fmt.Sprintf("%d", tls.X25519)})
	require.NoError(t, err)
	require.Equal(t, []tls.CurveID{tls.X25519}, curves)
}
