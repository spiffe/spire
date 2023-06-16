package run

import (
	"crypto/x509/pkix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server"
	bundleClient "github.com/spiffe/spire/pkg/server/bundle/client"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mergeInputCase struct {
	msg       string
	fileInput func(*Config)
	cliFlags  []string
	test      func(*testing.T, *Config)
}

type newServerConfigCase struct {
	msg         string
	expectError bool
	input       func(*Config)
	logOptions  func(t *testing.T) []log.Option
	test        func(*testing.T, *server.Config)
}

func TestParseConfigGood(t *testing.T) {
	c, err := ParseFile(configFile, false)
	require.NoError(t, err)

	// Check for server configurations
	assert.Equal(t, c.Server.BindAddress, "127.0.0.1")
	assert.Equal(t, c.Server.BindPort, 8081)
	assert.Equal(t, c.Server.TrustDomain, "example.org")
	assert.Equal(t, c.Server.LogLevel, "INFO")
	assert.Equal(t, c.Server.Federation.BundleEndpoint.Address, "0.0.0.0")
	assert.Equal(t, c.Server.Federation.BundleEndpoint.Port, 8443)
	assert.Equal(t, c.Server.Federation.BundleEndpoint.ACME.DomainName, "example.org")
	assert.Equal(t, 4, len(c.Server.Federation.FederatesWith))
	assert.Equal(t, c.Server.Federation.FederatesWith["domain3.test"].BundleEndpointURL, "https://9.10.11.12:8443")
	trustDomainConfig, err := parseBundleEndpointProfile(c.Server.Federation.FederatesWith["domain3.test"])
	assert.NoError(t, err)
	assert.Equal(t, trustDomainConfig.EndpointProfile.(bundleClient.HTTPSSPIFFEProfile).EndpointSPIFFEID, spiffeid.RequireFromString("spiffe://different-domain.test/my-spiffe-bundle-endpoint-server"))
	assert.Equal(t, c.Server.Federation.FederatesWith["domain4.test"].BundleEndpointURL, "https://13.14.15.16:8444")
	trustDomainConfig, err = parseBundleEndpointProfile(c.Server.Federation.FederatesWith["domain4.test"])
	assert.NoError(t, err)
	_, ok := trustDomainConfig.EndpointProfile.(bundleClient.HTTPSWebProfile)
	assert.True(t, ok)
	assert.True(t, c.Server.AuditLogEnabled)
	testParseConfigGoodOS(t, c)

	// Parse/reprint cycle trims outer whitespace
	const data = `join_token = "PLUGIN-SERVER-NOT-A-SECRET"`

	// Check for plugins configurations
	expectedPluginConfigs := catalog.PluginConfigs{
		{
			Type:     "plugin_type_server",
			Name:     "plugin_name_server",
			Path:     "./pluginServerCmd",
			Checksum: "pluginServerChecksum",
			Data:     data,
			Disabled: false,
		},
		{
			Type:     "plugin_type_server",
			Name:     "plugin_disabled",
			Path:     "./pluginServerCmd",
			Checksum: "pluginServerChecksum",
			Data:     data,
			Disabled: true,
		},
		{
			Type:     "plugin_type_server",
			Name:     "plugin_enabled",
			Path:     "./pluginServerCmd",
			Checksum: "pluginServerChecksum",
			Data:     data,
			Disabled: false,
		},
	}

	pluginConfigs, err := catalog.PluginConfigsFromHCLNode(c.Plugins)
	require.NoError(t, err)
	require.Equal(t, expectedPluginConfigs, pluginConfigs)
}

func TestMergeInput(t *testing.T) {
	cases := []mergeInputCase{
		{
			msg:       "bind_address should default to 0.0.0.0 if not set",
			fileInput: func(c *Config) {},
			cliFlags:  []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "0.0.0.0", c.Server.BindAddress)
			},
		},
		{
			msg: "bind_address should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.BindAddress = "10.0.0.1"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "10.0.0.1", c.Server.BindAddress)
			},
		},
		{
			msg: "bind_address should be configurable by CLI flag",
			fileInput: func(c *Config) {
				c.Server.BindAddress = ""
			},
			cliFlags: []string{"-bindAddress=10.0.0.1"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "10.0.0.1", c.Server.BindAddress)
			},
		},
		{
			msg: "bind_address specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.BindAddress = "10.0.0.1"
			},
			cliFlags: []string{"-bindAddress=10.0.0.2"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "10.0.0.2", c.Server.BindAddress)
			},
		},
		{
			msg:       "bind_port should default to 8081 if not set",
			fileInput: func(c *Config) {},
			cliFlags:  []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 8081, c.Server.BindPort)
			},
		},
		{
			msg: "bind_port should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.BindPort = 1337
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 1337, c.Server.BindPort)
			},
		},
		{
			msg:       "bind_port should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliFlags:  []string{"-serverPort=1337"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 1337, c.Server.BindPort)
			},
		},
		{
			msg: "bind_port specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.BindPort = 1336
			},
			cliFlags: []string{"-serverPort=1337"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 1337, c.Server.BindPort)
			},
		},
		{
			msg: "ca_key_type should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.CAKeyType = "rsa-2048"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "rsa-2048", c.Server.CAKeyType)
			},
		},
		{
			msg: "ca_subject should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.CASubject = &caSubjectConfig{
					Country:      []string{"test-country"},
					Organization: []string{"test-org"},
					CommonName:   "test-cn",
				}
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, []string{"test-country"}, c.Server.CASubject.Country)
				require.Equal(t, []string{"test-org"}, c.Server.CASubject.Organization)
				require.Equal(t, "test-cn", c.Server.CASubject.CommonName)
			},
		},
		{
			msg: "ca_ttl should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.CATTL = "1h"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "1h", c.Server.CATTL)
			},
		},
		{
			msg: "data_dir should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.DataDir = "foo"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.DataDir)
			},
		},
		{
			msg:       "data_dir should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliFlags:  []string{"-dataDir=foo"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.DataDir)
			},
		},
		{
			msg: "data_dir specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.DataDir = "foo"
			},
			cliFlags: []string{"-dataDir=bar"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.DataDir)
			},
		},
		{
			msg: "jwt_issuer should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.JWTIssuer = "ISSUER"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "ISSUER", c.Server.JWTIssuer)
			},
		},
		{
			msg: "log_file should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.LogFile = "foo"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.LogFile)
			},
		},
		{
			msg:       "log_file should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliFlags:  []string{"-logFile=foo"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.LogFile)
			},
		},
		{
			msg: "log_file specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.LogFile = "foo"
			},
			cliFlags: []string{"-logFile=bar"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.LogFile)
			},
		},
		{
			msg:       "log_format should default to log.DefaultFormat if not set",
			fileInput: func(c *Config) {},
			cliFlags:  []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, log.DefaultFormat, c.Server.LogFormat)
			},
		},
		{
			msg: "log_format should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.LogFormat = "JSON"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "JSON", c.Server.LogFormat)
			},
		},
		{
			msg:       "log_format should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliFlags:  []string{"-logFormat=JSON"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "JSON", c.Server.LogFormat)
			},
		},
		{
			msg: "log_format specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.LogFormat = "TEXT"
			},
			cliFlags: []string{"-logFormat=JSON"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "JSON", c.Server.LogFormat)
			},
		},
		{
			msg:       "log_level should default to INFO if not set",
			fileInput: func(c *Config) {},
			cliFlags:  []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "INFO", c.Server.LogLevel)
			},
		},
		{
			msg: "log_level should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.LogLevel = "DEBUG"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "DEBUG", c.Server.LogLevel)
			},
		},
		{
			msg:       "log_level should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliFlags:  []string{"-logLevel=DEBUG"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "DEBUG", c.Server.LogLevel)
			},
		},
		{
			msg: "log_level specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.LogLevel = "WARN"
			},
			cliFlags: []string{"-logLevel=DEBUG"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "DEBUG", c.Server.LogLevel)
			},
		},
		{
			msg: "default_x509_svid_ttl should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.DefaultX509SVIDTTL = "2h"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "2h", c.Server.DefaultX509SVIDTTL)
			},
		},
		{
			msg: "default_jwt_svid_ttl should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.DefaultJWTSVIDTTL = "3h"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "3h", c.Server.DefaultJWTSVIDTTL)
			},
		},
		{
			msg:       "trust_domain should not have a default value",
			fileInput: func(c *Config) {},
			cliFlags:  []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "", c.Server.TrustDomain)
			},
		},
		{
			msg: "trust_domain should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.TrustDomain = "foo"
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.TrustDomain)
			},
		},
		{
			// TODO: should it really?
			msg:       "trust_domain should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliFlags:  []string{"-trustDomain=foo"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.TrustDomain)
			},
		},
		{
			msg: "trust_domain specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.TrustDomain = "foo"
			},
			cliFlags: []string{"-trustDomain=bar"},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.TrustDomain)
			},
		},
		{
			msg: "audit_log_enabled should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.AuditLogEnabled = true
			},
			cliFlags: []string{},
			test: func(t *testing.T, c *Config) {
				require.True(t, c.Server.AuditLogEnabled)
			},
		},
	}
	cases = append(cases, mergeInputCasesOS(t)...)

	for _, testCase := range cases {
		testCase := testCase

		fileInput := &Config{Server: &serverConfig{}}

		testCase.fileInput(fileInput)
		cliInput, err := parseFlags("run", testCase.cliFlags, os.Stderr)
		require.NoError(t, err)

		t.Run(testCase.msg, func(t *testing.T) {
			i, err := mergeInput(fileInput, cliInput)
			require.NoError(t, err)

			testCase.test(t, i)
		})
	}
}

func TestNewServerConfig(t *testing.T) {
	assertLogsContainEntries := func(expectedEntries []spiretest.LogEntry) func(t *testing.T) []log.Option {
		return func(t *testing.T) []log.Option {
			return []log.Option{
				func(logger *log.Logger) error {
					logger.SetOutput(io.Discard)
					hook := test.NewLocal(logger.Logger)
					t.Cleanup(func() {
						spiretest.AssertLogsContainEntries(t, hook.AllEntries(), expectedEntries)
					})
					return nil
				},
			}
		}
	}

	cases := []newServerConfigCase{
		{
			msg: "bind_address and bind_port should be correctly parsed",
			input: func(c *Config) {
				c.Server.BindAddress = "192.168.1.1"
				c.Server.BindPort = 1337
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "192.168.1.1", c.BindAddress.IP.String())
				require.Equal(t, 1337, c.BindAddress.Port)
			},
		},
		{
			msg: "bind_address with hostname value should be correctly parsed",
			input: func(c *Config) {
				c.Server.BindAddress = "localhost"
				c.Server.BindPort = 1337
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "127.0.0.1", c.BindAddress.IP.String())
			},
		},
		{
			msg:         "invalid bind_address should return an error",
			expectError: true,
			input: func(c *Config) {
				c.Server.BindAddress = "this-is-not-an-ip-address"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:         "invalid bind_port should return an error",
			expectError: true,
			input: func(c *Config) {
				c.Server.BindAddress = "localhost"
				c.Server.BindPort = -1337
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "data_dir should be correctly configured",
			input: func(c *Config) {
				c.Server.DataDir = "foo"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "foo", c.DataDir)
			},
		},
		{
			msg: "trust_domain should be correctly parsed",
			input: func(c *Config) {
				c.Server.TrustDomain = "foo"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "spiffe://foo", c.TrustDomain.IDString())
			},
		},
		{
			msg:         "invalid trust_domain should return an error",
			expectError: true,
			input: func(c *Config) {
				c.Server.TrustDomain = "i'm invalid"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "jwt_issuer is correctly configured",
			input: func(c *Config) {
				c.Server.JWTIssuer = "ISSUER"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "ISSUER", c.JWTIssuer)
			},
		},
		{
			msg: "logger gets set correctly",
			input: func(c *Config) {
				c.Server.LogLevel = "WARN"
				c.Server.LogFormat = "TEXT"
			},
			test: func(t *testing.T, c *server.Config) {
				require.NotNil(t, c.Log)

				l := c.Log.(*log.Logger)
				require.Equal(t, logrus.WarnLevel, l.Level)
				require.IsType(t, &logrus.TextFormatter{}, l.Formatter)
			},
		},
		{
			msg: "log_level and log_format are case insensitive",
			input: func(c *Config) {
				c.Server.LogLevel = "wArN"
				c.Server.LogFormat = "TeXt"
			},
			test: func(t *testing.T, c *server.Config) {
				require.NotNil(t, c.Log)

				l := c.Log.(*log.Logger)
				require.Equal(t, logrus.WarnLevel, l.Level)
				require.IsType(t, &logrus.TextFormatter{}, l.Formatter)
			},
		},
		{
			msg:         "invalid log_level returns an error",
			expectError: true,
			input: func(c *Config) {
				c.Server.LogLevel = "not-a-valid-level"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:         "invalid log_format returns an error",
			expectError: true,
			input: func(c *Config) {
				c.Server.LogFormat = "not-a-valid-format"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "bundle endpoint is parsed and configured correctly",
			input: func(c *Config) {
				c.Server.Federation = &federationConfig{
					BundleEndpoint: &bundleEndpointConfig{
						Address: "192.168.1.1",
						Port:    1337,
					},
				}
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "192.168.1.1", c.Federation.BundleEndpoint.Address.IP.String())
				require.Equal(t, 1337, c.Federation.BundleEndpoint.Address.Port)
			},
		},
		{
			msg: "bundle federates with section is parsed and configured correctly",
			input: func(c *Config) {
				c.Server.Federation = &federationConfig{
					FederatesWith: map[string]federatesWithConfig{
						"domain1.test": httpsSPIFFEConfigTest(t),
						"domain2.test": webPKIConfigTest(t),
					},
				}
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, map[spiffeid.TrustDomain]bundleClient.TrustDomainConfig{
					spiffeid.RequireTrustDomainFromString("domain1.test"): {
						EndpointURL: "https://192.168.1.1:1337",
						EndpointProfile: bundleClient.HTTPSSPIFFEProfile{
							EndpointSPIFFEID: spiffeid.RequireFromString("spiffe://domain1.test/bundle/endpoint"),
						},
					},
					spiffeid.RequireTrustDomainFromString("domain2.test"): {
						EndpointURL:     "https://192.168.1.1:1337",
						EndpointProfile: bundleClient.HTTPSWebProfile{},
					},
				}, c.Federation.FederatesWith)
			},
		},
		{
			msg: "default_x509_svid_ttl is correctly parsed",
			input: func(c *Config) {
				c.Server.DefaultX509SVIDTTL = "2m"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, 2*time.Minute, c.X509SVIDTTL)
			},
		},
		{
			msg: "default_jwt_svid_ttl is correctly parsed",
			input: func(c *Config) {
				c.Server.DefaultJWTSVIDTTL = "3m"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, 3*time.Minute, c.JWTSVIDTTL)
			},
		},
		{
			msg:         "invalid default_x509_svid_ttl returns an error",
			expectError: true,
			input: func(c *Config) {
				c.Server.DefaultX509SVIDTTL = "b"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:         "invalid default_jwt_svid_ttl returns an error",
			expectError: true,
			input: func(c *Config) {
				c.Server.DefaultJWTSVIDTTL = "b"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "ca_key_type and jwt_key_type are set as default",
			input: func(c *Config) {
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.ECP256, c.CAKeyType)
				require.Equal(t, keymanager.ECP256, c.JWTKeyType)
			},
		},
		{
			msg: "rsa-2048 ca_key_type is correctly parsed and is set as default for jwt key",
			input: func(c *Config) {
				c.Server.CAKeyType = "rsa-2048"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.RSA2048, c.CAKeyType)
				require.Equal(t, keymanager.RSA2048, c.JWTKeyType)
			},
		},
		{
			msg: "rsa-4096 ca_key_type is correctly parsed and is set as default for jwt key",
			input: func(c *Config) {
				c.Server.CAKeyType = "rsa-4096"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.RSA4096, c.CAKeyType)
				require.Equal(t, keymanager.RSA4096, c.JWTKeyType)
			},
		},
		{
			msg: "ec-p256 ca_key_type is correctly parsed and is set as default for jwt key",
			input: func(c *Config) {
				c.Server.CAKeyType = "ec-p256"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.ECP256, c.CAKeyType)
				require.Equal(t, keymanager.ECP256, c.JWTKeyType)
			},
		},
		{
			msg: "ec-p384 ca_key_type is correctly parsed and is set as default for jwt key",
			input: func(c *Config) {
				c.Server.CAKeyType = "ec-p384"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.ECP384, c.CAKeyType)
				require.Equal(t, keymanager.ECP384, c.JWTKeyType)
			},
		},
		{
			msg:         "unsupported ca_key_type is rejected",
			expectError: true,
			input: func(c *Config) {
				c.Server.CAKeyType = "rsa-1024"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "rsa-2048 jwt_key_type is correctly parsed and ca_key_type is unspecified",
			input: func(c *Config) {
				c.Server.JWTKeyType = "rsa-2048"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.ECP256, c.CAKeyType)
				require.Equal(t, keymanager.RSA2048, c.JWTKeyType)
			},
		},
		{
			msg: "rsa-4096 jwt_key_type is correctly parsed and ca_key_type is unspecified",
			input: func(c *Config) {
				c.Server.JWTKeyType = "rsa-4096"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.ECP256, c.CAKeyType)
				require.Equal(t, keymanager.RSA4096, c.JWTKeyType)
			},
		},
		{
			msg: "ec-p256 jwt_key_type is correctly parsed and ca_key_type is unspecified",
			input: func(c *Config) {
				c.Server.JWTKeyType = "ec-p256"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.ECP256, c.CAKeyType)
				require.Equal(t, keymanager.ECP256, c.JWTKeyType)
			},
		},
		{
			msg: "ec-p384 jwt_key_type is correctly parsed and ca_key_type is unspecified",
			input: func(c *Config) {
				c.Server.JWTKeyType = "ec-p384"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.ECP256, c.CAKeyType)
				require.Equal(t, keymanager.ECP384, c.JWTKeyType)
			},
		},
		{
			msg:         "unsupported jwt_key_type is rejected",
			expectError: true,
			input: func(c *Config) {
				c.Server.JWTKeyType = "rsa-1024"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "override jwt_key_type from the default ca_key_type",
			input: func(c *Config) {
				c.Server.CAKeyType = "rsa-2048"
				c.Server.JWTKeyType = "ec-p256"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.RSA2048, c.CAKeyType)
				require.Equal(t, keymanager.ECP256, c.JWTKeyType)
			},
		},
		{
			msg: "ca_ttl is correctly parsed",
			input: func(c *Config) {
				c.Server.CATTL = "1h"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, time.Hour, c.CATTL)
			},
		},
		{
			msg:         "invalid ca_ttl returns an error",
			expectError: true,
			input: func(c *Config) {
				c.Server.CATTL = "b"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "ca_subject is defaulted when unset",
			input: func(c *Config) {
				c.Server.CASubject = nil
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, credtemplate.DefaultX509CASubject(), c.CASubject)
			},
		},
		{
			msg: "ca_subject is defaulted when set but empty",
			input: func(c *Config) {
				c.Server.CASubject = &caSubjectConfig{}
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, credtemplate.DefaultX509CASubject(), c.CASubject)
			},
		},
		{
			msg: "ca_subject is overridable",
			input: func(c *Config) {
				c.Server.CASubject = &caSubjectConfig{
					Organization: []string{"foo"},
					Country:      []string{"us"},
					CommonName:   "bar",
				}
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, pkix.Name{
					Organization: []string{"foo"},
					Country:      []string{"us"},
					CommonName:   "bar",
				}, c.CASubject)
			},
		},
		{
			msg: "attestation rate limit is on by default",
			input: func(c *Config) {
			},
			test: func(t *testing.T, c *server.Config) {
				require.True(t, c.RateLimit.Attestation)
			},
		},
		{
			msg: "attestation rate limits can be explicitly disabled",
			input: func(c *Config) {
				value := false
				c.Server.RateLimit.Attestation = &value
			},
			test: func(t *testing.T, c *server.Config) {
				require.False(t, c.RateLimit.Attestation)
			},
		},
		{
			msg: "attestation rate limits can be explicitly enabled",
			input: func(c *Config) {
				value := true
				c.Server.RateLimit.Attestation = &value
			},
			test: func(t *testing.T, c *server.Config) {
				require.True(t, c.RateLimit.Attestation)
			},
		},
		{
			msg: "signing rate limit is on by default",
			input: func(c *Config) {
			},
			test: func(t *testing.T, c *server.Config) {
				require.True(t, c.RateLimit.Signing)
			},
		},
		{
			msg: "signing rate limit can be explicitly disabled",
			input: func(c *Config) {
				value := false
				c.Server.RateLimit.Signing = &value
			},
			test: func(t *testing.T, c *server.Config) {
				require.False(t, c.RateLimit.Signing)
			},
		},
		{
			msg: "signing rate limit can be explicitly enabled",
			input: func(c *Config) {
				value := true
				c.Server.RateLimit.Signing = &value
			},
			test: func(t *testing.T, c *server.Config) {
				require.True(t, c.RateLimit.Signing)
			},
		},
		{
			msg: "warn_on_long_trust_domain",
			input: func(c *Config) {
				c.Server.TrustDomain = strings.Repeat("a", 256)
			},
			logOptions: assertLogsContainEntries([]spiretest.LogEntry{
				{
					Data:  map[string]interface{}{"trust_domain": strings.Repeat("a", 256)},
					Level: logrus.WarnLevel,
					Message: "Configured trust domain name should be less than 255 characters to be " +
						"SPIFFE compliant; a longer trust domain name may impact interoperability",
				},
			}),
			test: func(t *testing.T, c *server.Config) {
				assert.NotNil(t, c)
			},
		},
		{
			msg: "cache_reload_interval is correctly parsed",
			input: func(c *Config) {
				c.Server.Experimental.CacheReloadInterval = "1m"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, time.Minute, c.CacheReloadInterval)
			},
		},
		{
			msg:         "invalid cache_reload_interval returns an error",
			expectError: true,
			input: func(c *Config) {
				c.Server.Experimental.CacheReloadInterval = "b"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "audit_log_enabled is enabled",
			input: func(c *Config) {
				c.Server.AuditLogEnabled = true
			},
			test: func(t *testing.T, c *server.Config) {
				require.True(t, c.AuditLogEnabled)
			},
		},
		{
			msg: "audit_log_enabled is disabled",
			input: func(c *Config) {
				c.Server.AuditLogEnabled = false
			},
			test: func(t *testing.T, c *server.Config) {
				require.False(t, c.AuditLogEnabled)
			},
		},
		{
			msg: "admin IDs are set",
			input: func(c *Config) {
				c.Server.AdminIDs = []string{
					"spiffe://example.org/my/admin1",
					"spiffe://example.org/my/admin2",
				}
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, []spiffeid.ID{
					spiffeid.RequireFromString("spiffe://example.org/my/admin1"),
					spiffeid.RequireFromString("spiffe://example.org/my/admin2"),
				}, c.AdminIDs)
			},
		},
		{
			msg: "admin ID of foreign trust domain",
			input: func(c *Config) {
				c.Server.AdminIDs = []string{
					"spiffe://otherdomain.test/my/admin",
				}
			},
			expectError: false,
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, []spiffeid.ID{
					spiffeid.RequireFromString("spiffe://otherdomain.test/my/admin"),
				}, c.AdminIDs)
			},
		},
	}
	cases = append(cases, newServerConfigCasesOS()...)

	for _, testCase := range cases {
		testCase := testCase

		input := defaultValidConfig()

		testCase.input(input)

		t.Run(testCase.msg, func(t *testing.T) {
			var logOpts []log.Option
			if testCase.logOptions != nil {
				logOpts = testCase.logOptions(t)
			}

			sc, err := NewServerConfig(input, logOpts, false)
			if testCase.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			testCase.test(t, sc)
		})
	}
}

// defaultValidConfig returns the bare minimum config required to
// pass validation etc
func defaultValidConfig() *Config {
	c := defaultConfig()

	c.Server.DataDir = "."
	c.Server.TrustDomain = "example.org"

	c.Plugins = &ast.ObjectList{}

	return c
}

func TestValidateConfig(t *testing.T) {
	testCases := []struct {
		name        string
		applyConf   func(*Config)
		expectedErr string
	}{
		{
			name:        "server section must be configured",
			applyConf:   func(c *Config) { c.Server = nil },
			expectedErr: "server section must be configured",
		},
		{
			name:        "bind_address must be configured",
			applyConf:   func(c *Config) { c.Server.BindAddress = "" },
			expectedErr: "bind_address and bind_port must be configured",
		},
		{
			name:        "bind_port must be configured",
			applyConf:   func(c *Config) { c.Server.BindPort = 0 },
			expectedErr: "bind_address and bind_port must be configured",
		},
		{
			name:        "trust_domain must be configured",
			applyConf:   func(c *Config) { c.Server.TrustDomain = "" },
			expectedErr: "trust_domain must be configured",
		},
		{
			name:        "data_dir must be configured",
			applyConf:   func(c *Config) { c.Server.DataDir = "" },
			expectedErr: "data_dir must be configured",
		},
		{
			name:        "plugins section must be configured",
			applyConf:   func(c *Config) { c.Plugins = nil },
			expectedErr: "plugins section must be configured",
		},
		{
			name: "if ACME is used, federation.bundle_endpoint.acme.domain_name must be configured",
			applyConf: func(c *Config) {
				c.Server.Federation = &federationConfig{
					BundleEndpoint: &bundleEndpointConfig{
						ACME: &bundleEndpointACMEConfig{},
					},
				}
			},
			expectedErr: "federation.bundle_endpoint.acme.domain_name must be configured",
		},
		{
			name: "if ACME is used, federation.bundle_endpoint.acme.email must be configured",
			applyConf: func(c *Config) {
				c.Server.Federation = &federationConfig{
					BundleEndpoint: &bundleEndpointConfig{
						ACME: &bundleEndpointACMEConfig{
							DomainName: "domain-name",
						},
					},
				}
			},
			expectedErr: "federation.bundle_endpoint.acme.email must be configured",
		},
		{
			name: "bundle_endpoint_url must be configured if federates_with is configured",
			applyConf: func(c *Config) {
				federatesWith := make(map[string]federatesWithConfig)
				federatesWith["domain.test"] = federatesWithConfig{}
				c.Server.Federation = &federationConfig{
					FederatesWith: federatesWith,
				}
			},
			expectedErr: "federation.federates_with[\"domain.test\"].bundle_endpoint_url must be configured",
		},
		{
			name: "bundle_endpoint_url must use the HTTPS protocol",
			applyConf: func(c *Config) {
				federatesWith := make(map[string]federatesWithConfig)
				federatesWith["domain.test"] = federatesWithConfig{
					BundleEndpointURL: "http://example.org/test",
				}
				c.Server.Federation = &federationConfig{
					FederatesWith: federatesWith,
				}
			},
			expectedErr: `federation.federates_with["domain.test"].bundle_endpoint_url must use the HTTPS protocol; URL found: "http://example.org/test"`,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			conf := defaultValidConfig()
			testCase.applyConf(conf)
			err := validateConfig(conf)
			if testCase.expectedErr != "" {
				require.Error(t, err)
				spiretest.AssertErrorContains(t, err, testCase.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWarnOnUnknownConfig(t *testing.T) {
	testFileDir := "../../../../test/fixture/config"

	type logEntry struct {
		section string
		keys    string
	}

	cases := []struct {
		msg                string
		confFile           string
		expectedLogEntries []logEntry
	}{
		{
			msg:      "in root block",
			confFile: "server_and_agent_bad_root_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "top-level",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		{
			msg:      "in server block",
			confFile: "server_bad_server_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "server",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		{
			msg:      "in nested ca_subject block",
			confFile: "server_bad_nested_ca_subject_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "ca_subject",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		{
			msg:      "in ratelimit block",
			confFile: "server_bad_ratelimit_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "ratelimit",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		// TODO: Re-enable unused key detection for experimental config. See
		// https://github.com/spiffe/spire/issues/1101 for more information
		//
		// {
		//	msg:            "in nested experimental block",
		//	confFile: "/server_bad_nested_experimental_block.conf",
		//	expectedLogEntries: []logEntry{
		//		{
		//			section: "experimental",
		//			keys: 		"unknown_option1,unknown_option2",
		//		},
		//	},
		// },
		// {
		//	msg:            "in nested federation block",
		//	confFile: "/server_bad_nested_federation_block.conf",
		//	expectedLogEntries: []logEntry{
		//		{
		//			section: "federation",
		//			keys: "unknown_option1,unknown_option2",
		//		},
		//	},
		// },
		{
			msg:      "in nested federation.bundle_endpoint block",
			confFile: "server_bad_nested_bundle_endpoint_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "bundle endpoint",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		{
			msg:      "in nested bundle_endpoint.acme block",
			confFile: "server_bad_nested_bundle_endpoint_acme_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "bundle endpoint ACME",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		// TODO: Re-enable unused key detection for experimental config. See
		// https://github.com/spiffe/spire/issues/1101 for more information
		//
		// {
		//	msg:      "in nested federates_with block",
		//	confFile: "server_bad_nested_federates_with_block.conf",
		//	expectedLogEntries: []logEntry{
		//		{
		//			section: `federates_with "test1"`,
		//			keys:    "unknown_option1,unknown_option2",
		//		},
		//		{
		//			section: `federates_with "test2"`,
		//			keys:    "unknown_option1,unknown_option2",
		//		},
		//	},
		// },
		// {
		//	msg:            "in telemetry block",
		//	confFile: "/server_and_agent_bad_telemetry_block.conf",
		//	expectedLogEntries: []logEntry{
		//		{
		//			section: "telemetry",
		//			keys: "unknown_option1,unknown_option2",
		//		},
		//	},
		// },
		{
			msg:      "in nested Prometheus block",
			confFile: "server_and_agent_bad_nested_Prometheus_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "Prometheus",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		{
			msg:      "in nested DogStatsd block",
			confFile: "server_and_agent_bad_nested_DogStatsd_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "DogStatsd",
					keys:    "unknown_option1,unknown_option2",
				},
				{
					section: "DogStatsd",
					keys:    "unknown_option3,unknown_option4",
				},
			},
		},
		{
			msg:      "in nested Statsd block",
			confFile: "server_and_agent_bad_nested_Statsd_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "Statsd",
					keys:    "unknown_option1,unknown_option2",
				},
				{
					section: "Statsd",
					keys:    "unknown_option3,unknown_option4",
				},
			},
		},
		{
			msg:      "in nested M3 block",
			confFile: "server_and_agent_bad_nested_M3_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "M3",
					keys:    "unknown_option1,unknown_option2",
				},
				{
					section: "M3",
					keys:    "unknown_option3,unknown_option4",
				},
			},
		},
		{
			msg:      "in nested InMem block",
			confFile: "server_and_agent_bad_nested_InMem_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "InMem",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		{
			msg:      "in nested health_checks block",
			confFile: "server_and_agent_bad_nested_health_checks_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: "health check",
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
	}

	for _, testCase := range cases {
		testCase := testCase

		c, err := ParseFile(filepath.Join(testFileDir, testCase.confFile), false)
		require.NoError(t, err)

		t.Run(testCase.msg, func(t *testing.T) {
			log, hook := test.NewNullLogger()
			err := checkForUnknownConfig(c, log)
			assert.EqualError(t, err, "unknown configuration detected")

			var logEntries []spiretest.LogEntry
			for _, expectedLogEntry := range testCase.expectedLogEntries {
				logEntries = append(logEntries, spiretest.LogEntry{
					Level:   logrus.ErrorLevel,
					Message: "Unknown configuration detected",
					Data: logrus.Fields{
						"section": expectedLogEntry.section,
						"keys":    expectedLogEntry.keys,
					},
				})
			}
			spiretest.AssertLogsContainEntries(t, hook.AllEntries(), logEntries)
		})
	}
}

// TestLogOptions verifies the log options given to newAgentConfig are applied, and are overridden
// by values from the config file
func TestLogOptions(t *testing.T) {
	fd, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	require.NoError(t, fd.Close())
	defer os.Remove(fd.Name())

	logFile, err := log.NewReopenableFile(fd.Name())
	require.NoError(t, err)
	logOptions := []log.Option{
		log.WithLevel("DEBUG"),
		log.WithFormat(log.JSONFormat),
		log.WithReopenableOutputFile(logFile),
	}

	agentConfig, err := NewServerConfig(defaultValidConfig(), logOptions, false)
	require.NoError(t, err)

	logger := agentConfig.Log.(*log.Logger).Logger

	// defaultConfig() sets level to info,  which should override DEBUG set above
	require.Equal(t, logrus.InfoLevel, logger.Level)

	// JSON Formatter and output file should be set from above
	require.IsType(t, &logrus.JSONFormatter{}, logger.Formatter)
	require.Equal(t, fd.Name(), logger.Out.(*log.ReopenableFile).Name())
}

func TestHasCompatibleTTLs(t *testing.T) {
	cases := []struct {
		msg                      string
		caTTL                    time.Duration
		x509SvidTTL              time.Duration
		jwtSvidTTL               time.Duration
		hasCompatibleSvidTTL     bool
		hasCompatibleX509SvidTTL bool
		hasCompatibleJwtSvidTTL  bool
	}{
		{
			msg:                      "All values are default values",
			caTTL:                    0,
			x509SvidTTL:              0,
			jwtSvidTTL:               0,
			hasCompatibleX509SvidTTL: true,
			hasCompatibleJwtSvidTTL:  true,
		},
		{
			msg:                      "ca_ttl is large enough for all default SVID TTL",
			caTTL:                    time.Hour * 7,
			x509SvidTTL:              0,
			jwtSvidTTL:               0,
			hasCompatibleX509SvidTTL: true,
			hasCompatibleJwtSvidTTL:  true,
		},
		{
			msg:                      "ca_ttl is not large enough for the default SVID TTL",
			caTTL:                    time.Minute * 1,
			x509SvidTTL:              0,
			jwtSvidTTL:               0,
			hasCompatibleX509SvidTTL: false,
			hasCompatibleJwtSvidTTL:  false,
		},
		{
			msg:                      "default_x509_svid_ttl is small enough for the default CA TTL",
			caTTL:                    0,
			x509SvidTTL:              time.Hour * 3,
			jwtSvidTTL:               0,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: true,
			hasCompatibleJwtSvidTTL:  true,
		},
		{
			msg:                      "default_x509_svid_ttl is not small enough for the default CA TTL",
			caTTL:                    0,
			x509SvidTTL:              time.Hour * 24,
			jwtSvidTTL:               0,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: false,
			hasCompatibleJwtSvidTTL:  true,
		},
		{
			msg:                      "default_x509_svid_ttl is small enough for the configured CA TTL",
			caTTL:                    time.Hour * 24,
			x509SvidTTL:              time.Hour * 1,
			jwtSvidTTL:               0,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: true,
			hasCompatibleJwtSvidTTL:  true,
		},
		{
			msg:                      "default_x509_svid_ttl is not small enough for the configured CA TTL",
			caTTL:                    time.Hour * 24,
			x509SvidTTL:              time.Hour * 23,
			jwtSvidTTL:               0,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: false,
			hasCompatibleJwtSvidTTL:  true,
		},
		{
			msg:                      "default_x509_svid_ttl is larger than the configured CA TTL",
			caTTL:                    time.Hour * 24,
			x509SvidTTL:              time.Hour * 25,
			jwtSvidTTL:               0,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: false,
			hasCompatibleJwtSvidTTL:  true,
		},
		{
			msg:                      "default_x509_svid_ttl is small enough for the configured CA TTL but larger than the max",
			caTTL:                    time.Hour * 24 * 7 * 4 * 6, // Six months
			x509SvidTTL:              time.Hour * 24 * 7 * 2,     // Two weeks,
			jwtSvidTTL:               0,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: false,
			hasCompatibleJwtSvidTTL:  true,
		},
		{
			msg:                      "default_jwt_svid_ttl is small enough for the default CA TTL",
			caTTL:                    0,
			x509SvidTTL:              0,
			jwtSvidTTL:               time.Hour * 3,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: true,
			hasCompatibleJwtSvidTTL:  true,
		},
		{
			msg:                      "default_jwt_svid_ttl is not small enough for the default CA TTL",
			caTTL:                    0,
			x509SvidTTL:              0,
			jwtSvidTTL:               time.Hour * 24,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: true,
			hasCompatibleJwtSvidTTL:  false,
		},
		{
			msg:                      "default_jwt_svid_ttl is small enough for the configured CA TTL",
			caTTL:                    time.Hour * 24,
			x509SvidTTL:              0,
			jwtSvidTTL:               time.Hour * 1,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: true,
			hasCompatibleJwtSvidTTL:  true,
		},
		{
			msg:                      "default_jwt_svid_ttl is not small enough for the configured CA TTL",
			caTTL:                    time.Hour * 24,
			x509SvidTTL:              0,
			jwtSvidTTL:               time.Hour * 23,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: true,
			hasCompatibleJwtSvidTTL:  false,
		},
		{
			msg:                      "default_jwt_svid_ttl is larger than the configured CA TTL",
			caTTL:                    time.Hour * 24,
			x509SvidTTL:              0,
			jwtSvidTTL:               time.Hour * 25,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: true,
			hasCompatibleJwtSvidTTL:  false,
		},
		{
			msg:                      "default_jwt_svid_ttl is small enough for the configured CA TTL but larger than the max",
			caTTL:                    time.Hour * 24 * 7 * 4 * 6, // Six months
			x509SvidTTL:              0,
			jwtSvidTTL:               time.Hour * 24 * 7 * 2, // Two weeks,,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: true,
			hasCompatibleJwtSvidTTL:  false,
		},
		{
			msg:                      "all default svid_ttls are small enough for the configured CA TTL",
			caTTL:                    time.Hour * 24,
			x509SvidTTL:              time.Hour * 1,
			jwtSvidTTL:               time.Hour * 1,
			hasCompatibleSvidTTL:     true,
			hasCompatibleX509SvidTTL: true,
			hasCompatibleJwtSvidTTL:  true,
		},
	}

	for _, testCase := range cases {
		testCase := testCase
		if testCase.caTTL == 0 {
			testCase.caTTL = credtemplate.DefaultX509CATTL
		}
		if testCase.x509SvidTTL == 0 {
			testCase.x509SvidTTL = credtemplate.DefaultX509SVIDTTL
		}
		if testCase.jwtSvidTTL == 0 {
			testCase.jwtSvidTTL = credtemplate.DefaultJWTSVIDTTL
		}

		t.Run(testCase.msg, func(t *testing.T) {
			require.Equal(t, testCase.hasCompatibleX509SvidTTL, hasCompatibleTTL(testCase.caTTL, testCase.x509SvidTTL))
			require.Equal(t, testCase.hasCompatibleJwtSvidTTL, hasCompatibleTTL(testCase.caTTL, testCase.jwtSvidTTL))
		})
	}
}

func TestMaxSVIDTTL(t *testing.T) {
	for _, v := range []struct {
		caTTL  time.Duration
		expect string
	}{
		{
			caTTL:  10 * time.Second,
			expect: "1s",
		},
		{
			caTTL:  15 * time.Second,
			expect: "2s",
		},
		{
			caTTL:  10 * time.Minute,
			expect: "1m40s",
		},
		{
			caTTL:  22 * time.Minute,
			expect: "3m40s",
		},
		{
			caTTL:  24 * time.Hour,
			expect: "4h",
		},
		{
			caTTL:  0,
			expect: "4h",
		},
	} {
		if v.caTTL == 0 {
			v.caTTL = credtemplate.DefaultX509CATTL
		}

		assert.Equal(t, v.expect, printMaxSVIDTTL(v.caTTL))
	}
}

func TestMinCATTL(t *testing.T) {
	for _, v := range []struct {
		x509SVIDTTL time.Duration
		jwtSVIDTTL  time.Duration
		expect      string
	}{
		{
			x509SVIDTTL: 10 * time.Second,
			jwtSVIDTTL:  1 * time.Second,
			expect:      "1m",
		},
		{
			x509SVIDTTL: 15 * time.Second,
			jwtSVIDTTL:  1 * time.Second,
			expect:      "1m30s",
		},
		{
			x509SVIDTTL: 10 * time.Minute,
			jwtSVIDTTL:  1 * time.Second,
			expect:      "1h",
		},
		{
			x509SVIDTTL: 22 * time.Minute,
			jwtSVIDTTL:  1 * time.Second,
			expect:      "2h12m",
		},
		{
			x509SVIDTTL: 24 * time.Hour,
			jwtSVIDTTL:  1 * time.Second,
			expect:      "144h",
		},
		{
			x509SVIDTTL: 0,
			jwtSVIDTTL:  1 * time.Second,
			expect:      "6h",
		},

		{
			x509SVIDTTL: 1 * time.Second,
			jwtSVIDTTL:  10 * time.Second,
			expect:      "1m",
		},
		{
			x509SVIDTTL: 1 * time.Second,
			jwtSVIDTTL:  15 * time.Second,
			expect:      "1m30s",
		},
		{
			x509SVIDTTL: 1 * time.Second,
			jwtSVIDTTL:  10 * time.Minute,
			expect:      "1h",
		},
		{
			x509SVIDTTL: 1 * time.Second,
			jwtSVIDTTL:  22 * time.Minute,
			expect:      "2h12m",
		},
		{
			x509SVIDTTL: 1 * time.Second,
			jwtSVIDTTL:  24 * time.Hour,
			expect:      "144h",
		},
		{
			x509SVIDTTL: 1 * time.Second,
			jwtSVIDTTL:  0,
			expect:      "30m",
		},
	} {
		if v.x509SVIDTTL == 0 {
			v.x509SVIDTTL = credtemplate.DefaultX509SVIDTTL
		}
		if v.jwtSVIDTTL == 0 {
			v.jwtSVIDTTL = credtemplate.DefaultJWTSVIDTTL
		}

		// The expected value is the MinCATTL calculated from the largest of the available TTLs
		if v.x509SVIDTTL > v.jwtSVIDTTL {
			assert.Equal(t, v.expect, printMinCATTL(v.x509SVIDTTL))
		} else {
			assert.Equal(t, v.expect, printMinCATTL(v.jwtSVIDTTL))
		}
	}
}

func TestExpandEnv(t *testing.T) {
	require.NoError(t, os.Setenv("TEST_DATA_TRUST_DOMAIN", "example.org"))

	cases := []struct {
		expandEnv     bool
		expectedValue string
	}{
		{
			expandEnv:     true,
			expectedValue: "example.org",
		},
		{
			expandEnv:     false,
			expectedValue: "$TEST_DATA_TRUST_DOMAIN",
		},
	}

	for _, testCase := range cases {
		c, err := ParseFile("../../../../test/fixture/config/server_good_templated.conf", testCase.expandEnv)
		require.NoError(t, err)
		assert.Equal(t, testCase.expectedValue, c.Server.TrustDomain)
	}
}

func TestAgentTTL(t *testing.T) {
	for _, c := range []struct {
		agentTTL         string
		expectedDuration time.Duration
	}{
		{
			agentTTL:         "168h",
			expectedDuration: 168 * time.Hour,
		},
		{
			agentTTL:         "",
			expectedDuration: 0,
		},
	} {
		config := defaultValidConfig()
		config.Server.AgentTTL = c.agentTTL
		sconfig, err := NewServerConfig(config, []log.Option{}, false)
		assert.NoError(t, err)
		assert.Equal(t, c.expectedDuration, sconfig.AgentTTL)
	}
}

func httpsSPIFFEConfigTest(t *testing.T) federatesWithConfig {
	configString := `bundle_endpoint_url = "https://192.168.1.1:1337"
	bundle_endpoint_profile "https_spiffe" {
		endpoint_spiffe_id = "spiffe://domain1.test/bundle/endpoint"
	}`
	httpsSPIFFEConfig := new(federatesWithConfig)
	require.NoError(t, hcl.Decode(httpsSPIFFEConfig, configString))

	return *httpsSPIFFEConfig
}

func webPKIConfigTest(t *testing.T) federatesWithConfig {
	configString := `bundle_endpoint_url = "https://192.168.1.1:1337"
		bundle_endpoint_profile "https_web" {}`
	webPKIConfig := new(federatesWithConfig)
	require.NoError(t, hcl.Decode(webPKIConfig, configString))

	return *webPKIConfig
}
