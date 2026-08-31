package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spiffe/spire/pkg/common/tlspolicy"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

type parseConfigCase struct {
	name string
	in   string
	out  *Config
	err  string
}

func TestLoadConfig(t *testing.T) {
	require := require.New(t)

	dir := spiretest.TempDir(t)

	confPath := filepath.Join(dir, "test.conf")

	_, err := LoadConfig(confPath, false)
	require.Error(err)
	require.Contains(err.Error(), "unable to load configuration:")

	err = os.WriteFile(confPath, []byte(minimalEnvServerAPIConfig), 0o600)
	require.NoError(err)

	os.Setenv("SPIFFE_TRUST_DOMAIN", "domain.test")
	config, err := LoadConfig(confPath, true)
	require.NoError(err)

	require.Equal(&Config{
		LogLevel: defaultLogLevel,
		Domains:  []string{"domain.test"},
		ACME: &ACMEConfig{
			CacheDir:    defaultCacheDir,
			Email:       "admin@domain.test",
			ToSAccepted: true,
		},
		ServerAPI: serverAPIConfig,
	}, config)

	err = os.WriteFile(confPath, []byte(minimalServerAPIConfig), 0o600)
	require.NoError(err)

	config, err = LoadConfig(confPath, false)
	require.NoError(err)

	require.Equal(&Config{
		LogLevel: defaultLogLevel,
		Domains:  []string{"domain.test"},
		ACME: &ACMEConfig{
			CacheDir:    defaultCacheDir,
			Email:       "admin@domain.test",
			ToSAccepted: true,
		},
		ServerAPI: serverAPIConfig,
	}, config)
}

func TestParseConfig(t *testing.T) {
	testCases := []parseConfigCase{
		{
			name: "malformed HCL",
			in:   `BAD`,
			err:  "unable to decode configuration",
		},
		{
			name: "no source section configured",
			in: `
				domains = ["domain.test"]
				acme {
					email = "admin@domain.test"
					tos_accepted = true
				}
			`,
			err: "exactly one of the server_api, workload_api, or file sections must be configured",
		},
	}
	testCases = append(testCases, parseConfigCasesOS()...)

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual, err := ParseConfig(testCase.in)
			if testCase.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), testCase.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.out, actual)
		})
	}
}

func TestParseTLSConfigFromHCL(t *testing.T) {
	serverAPISection := `
server_api {
    address = "unix:///some/socket/path"
}
`
	if runtime.GOOS == "windows" {
		serverAPISection = `
server_api {
    experimental {
        named_pipe_name = "\\name\\for\\server\\api"
    }
}
`
	}

	configString := `
domains = ["domain.test"]
tls_config {
    min_tls_version = "VersionTLS13"
    cipher_suites = [
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ]
    curve_preferences = [
        "X25519MLKEM768",
        "X25519",
        "secp256r1",
    ]
}
serving_cert_file {
    cert_file_path = "test.crt"
    key_file_path = "test.key"
}
` + serverAPISection
	c, err := ParseConfig(configString)
	require.NoError(t, err)

	require.NotNil(t, c.TLSConfig)
	require.Equal(t, "VersionTLS13", c.TLSConfig.MinTLSVersion)
	require.Equal(t, []string{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	}, c.TLSConfig.CipherSuites)
	require.Equal(t, []string{"X25519MLKEM768", "X25519", "secp256r1"}, c.TLSConfig.CurvePreferences)

	policy, err := tlspolicy.NewPolicy(false, c.TLSConfig, nil)
	require.NoError(t, err)
	require.NotNil(t, policy.TLSCfg)
	require.Equal(t, uint16(tls.VersionTLS13), policy.TLSCfg.MinTLSVersion)
	require.Nil(t, policy.TLSCfg.CipherSuites)
	require.Equal(t, []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}, policy.TLSCfg.CurvePreferences)
}

func TestApplyTLSPolicyWithInvalidServerTLSConfig(t *testing.T) {
	t.Run("invalid config fails at startup", func(t *testing.T) {
		_, err := tlspolicy.NewPolicy(false, &tlspolicy.TLSConfig{
			MinTLSVersion: "not-a-version",
		}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid minTLSVersion")
	})
}
