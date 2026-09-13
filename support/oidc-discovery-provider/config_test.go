package main

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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
			name: "log_file_rotation without log_path",
			in: `
				domains = ["domain.test"]
				log_file_rotation {
					max_size_mb = 100
				}
			`,
			err: "log_path must be configured to use the log_file_rotation configuration section",
		},
		{
			name: "log_file_rotation with a negative max_size_mb",
			in: `
				domains = ["domain.test"]
				log_path = "/tmp/oidc.log"
				log_file_rotation {
					max_size_mb = -1
				}
			`,
			err: "invalid log_file_rotation configuration section: max_size_mb (-1) must not be negative",
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

func TestParseConfigServingCertSource(t *testing.T) {
	serverAPI := "server_api {\n address = \"unix:///some/socket/path\"\n}"
	workloadAPI := "workload_api {\n socket_path = \"/some/socket/path\"\n trust_domain = \"domain.test\"\n}"
	if runtime.GOOS == "windows" {
		serverAPI = "server_api {\n experimental {\n named_pipe_name = \"\\\\name\\\\for\\\\server\\\\api\"\n }\n}"
		workloadAPI = "workload_api {\n experimental {\n named_pipe_name = \"\\\\name\\\\for\\\\workload\\\\api\"\n }\n trust_domain = \"domain.test\"\n}"
	}
	acme := "serving_cert_source \"acme\" {\n email = \"admin@domain.test\"\n tos_accepted = true\n}"

	for _, tt := range []struct {
		name  string
		in    string
		err   string
		check func(t *testing.T, c *Config)
	}{
		{
			name: "acme source is aliased to the acme section",
			in:   acme + serverAPI,
			check: func(t *testing.T, c *Config) {
				require.Equal(t, &ACMEConfig{CacheDir: defaultCacheDir, Email: "admin@domain.test", ToSAccepted: true}, c.ServingCertSource.ACME)
				require.Same(t, c.ServingCertSource.ACME, c.ACME)
			},
		},
		{
			name: "cert_file source is aliased to the serving_cert_file section",
			in:   "serving_cert_source \"cert_file\" {\n cert_file_path = \"test.crt\"\n key_file_path = \"test.key\"\n}" + serverAPI,
			check: func(t *testing.T, c *Config) {
				require.Same(t, c.ServingCertSource.CertFile, c.ServingCertFile)
				require.Equal(t, defaultAddr, c.ServingCertFile.RawAddr)
				require.Equal(t, time.Minute, c.ServingCertFile.FileSyncInterval)
			},
		},
		{
			name: "workload_api source with defaults",
			in:   "serving_cert_source \"workload_api\" {}" + workloadAPI,
			check: func(t *testing.T, c *Config) {
				require.Equal(t, &net.TCPAddr{Port: 443}, c.ServingCertSource.WorkloadAPI.Addr)
				require.Equal(t, c.WorkloadAPI.SocketPath, c.ServingCertSource.WorkloadAPI.SocketPath)
				require.Equal(t, c.WorkloadAPI.Experimental, c.ServingCertSource.WorkloadAPI.Experimental)
				require.Nil(t, c.ACME)
				require.Nil(t, c.ServingCertFile)
			},
		},
		{
			name: "workload_api source with addr",
			in:   "serving_cert_source \"workload_api\" {\n addr = \"127.0.0.1:9090\"\n}" + workloadAPI,
			check: func(t *testing.T, c *Config) {
				require.Equal(t, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, c.ServingCertSource.WorkloadAPI.Addr)
			},
		},
		{
			name: "workload_api source without a Workload API address",
			in:   "serving_cert_source \"workload_api\" {}" + serverAPI,
			err:  `must be configured in the serving_cert_source "workload_api" configuration section`,
		},
		{
			name: "workload_api source with insecure_addr",
			in:   "insecure_addr = \":8080\"\nserving_cert_source \"workload_api\" {}" + workloadAPI,
			err:  `serving_cert_source "workload_api" is mutually exclusive with insecure_addr`,
		},
		{
			name: "unknown source",
			in:   "serving_cert_source \"unknown\" {}" + serverAPI,
			err:  `serving_cert_source must be one of "acme", "cert_file", or "workload_api"`,
		},
		{
			name: "multiple sources",
			in:   acme + "serving_cert_source \"workload_api\" {}" + workloadAPI,
			err:  "only one serving_cert_source section can be configured",
		},
		{
			name: "mixed with the deprecated acme section",
			in:   "acme {\n email = \"admin@domain.test\"\n tos_accepted = true\n}\n" + acme + serverAPI,
			err:  "the acme and serving_cert_file sections cannot be used together with the serving_cert_source section",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ParseConfig("domains = [\"domain.test\"]\n" + tt.in)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			tt.check(t, c)
		})
	}
}
