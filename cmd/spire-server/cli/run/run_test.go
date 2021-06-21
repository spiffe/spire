package run

import (
	"bytes"
	"crypto/x509/pkix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server"
	bundleClient "github.com/spiffe/spire/pkg/server/bundle/client"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigGood(t *testing.T) {
	c, err := ParseFile("../../../../test/fixture/config/server_good.conf", false)
	require.NoError(t, err)

	// Check for server configurations
	assert.Equal(t, c.Server.BindAddress, "127.0.0.1")
	assert.Equal(t, c.Server.BindPort, 8081)
	assert.Empty(t, c.Server.DeprecatedRegistrationUDSPath)
	assert.Equal(t, c.Server.SocketPath, "/tmp/spire-server/private/api.sock")
	assert.Equal(t, c.Server.TrustDomain, "example.org")
	assert.Equal(t, c.Server.LogLevel, "INFO")
	assert.Equal(t, c.Server.Federation.BundleEndpoint.Address, "0.0.0.0")
	assert.Equal(t, c.Server.Federation.BundleEndpoint.Port, 8443)
	assert.Equal(t, c.Server.Federation.BundleEndpoint.ACME.DomainName, "example.org")
	assert.Equal(t, len(c.Server.Federation.FederatesWith), 2)
	assert.Equal(t, c.Server.Federation.FederatesWith["domain1.test"].BundleEndpoint.Address, "1.2.3.4")
	assert.True(t, c.Server.Federation.FederatesWith["domain1.test"].BundleEndpoint.UseWebPKI)
	assert.Equal(t, c.Server.Federation.FederatesWith["domain2.test"].BundleEndpoint.Address, "5.6.7.8")
	assert.Equal(t, c.Server.Federation.FederatesWith["domain2.test"].BundleEndpoint.SpiffeID, "spiffe://domain2.test/bundle-provider")

	// Check for plugins configurations
	pluginConfigs := *c.Plugins
	expectedData := "join_token = \"PLUGIN-SERVER-NOT-A-SECRET\""
	var data bytes.Buffer
	err = printer.DefaultConfig.Fprint(&data, pluginConfigs["plugin_type_server"]["plugin_name_server"].PluginData)
	assert.NoError(t, err)

	assert.Len(t, pluginConfigs, 1)
	assert.Len(t, pluginConfigs["plugin_type_server"], 3)

	// Default config
	pluginConfig := pluginConfigs["plugin_type_server"]["plugin_name_server"]
	assert.Nil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), true)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginServerChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, "./pluginServerCmd")
	assert.Equal(t, expectedData, data.String())

	// Disabled plugin
	pluginConfig = pluginConfigs["plugin_type_server"]["plugin_disabled"]
	assert.NotNil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), false)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginServerChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, "./pluginServerCmd")
	assert.Equal(t, expectedData, data.String())

	// Enabled plugin
	pluginConfig = pluginConfigs["plugin_type_server"]["plugin_enabled"]
	assert.NotNil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), true)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginServerChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, "./pluginServerCmd")
	assert.Equal(t, expectedData, data.String())
}

func TestParseFlagsGood(t *testing.T) {
	c, err := parseFlags("run", []string{
		"-bindAddress=127.0.0.1",
		"-socketPath=/tmp/flag.sock",
		"-trustDomain=example.org",
		"-logLevel=INFO",
	}, os.Stderr)
	require.NoError(t, err)
	assert.Equal(t, c.BindAddress, "127.0.0.1")
	assert.Equal(t, c.SocketPath, "/tmp/flag.sock")
	assert.Equal(t, c.TrustDomain, "example.org")
	assert.Equal(t, c.LogLevel, "INFO")
}

func TestMergeInput(t *testing.T) {
	cases := []struct {
		msg       string
		fileInput func(*Config)
		cliInput  func(*serverConfig)
		test      func(*testing.T, *Config)
	}{
		{
			msg:       "bind_address should default to 0.0.0.0 if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "0.0.0.0", c.Server.BindAddress)
			},
		},
		{
			msg: "bind_address should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.BindAddress = "10.0.0.1"
			},
			cliInput: func(c *serverConfig) {
				c.BindAddress = ""
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "10.0.0.1", c.Server.BindAddress)
			},
		},
		{
			msg: "bind_address should be configurable by CLI flag",
			fileInput: func(c *Config) {
				c.Server.BindAddress = ""
			},
			cliInput: func(c *serverConfig) {
				c.BindAddress = "10.0.0.1"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "10.0.0.1", c.Server.BindAddress)
			},
		},
		{
			msg: "bind_address specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.BindAddress = "10.0.0.1"
			},
			cliInput: func(c *serverConfig) {
				c.BindAddress = "10.0.0.2"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "10.0.0.2", c.Server.BindAddress)
			},
		},
		{
			msg:       "bind_port should default to 8081 if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 8081, c.Server.BindPort)
			},
		},
		{
			msg: "bind_port should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.BindPort = 1337
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 1337, c.Server.BindPort)
			},
		},
		{
			msg:       "bind_port should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *serverConfig) {
				c.BindPort = 1337
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 1337, c.Server.BindPort)
			},
		},
		{
			msg: "bind_port specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.BindPort = 1336
			},
			cliInput: func(c *serverConfig) {
				c.BindPort = 1337
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 1337, c.Server.BindPort)
			},
		},
		{
			msg: "ca_key_type should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.CAKeyType = "rsa-2048"
			},
			cliInput: func(c *serverConfig) {},
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
			cliInput: func(c *serverConfig) {},
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
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "1h", c.Server.CATTL)
			},
		},
		{
			msg: "data_dir should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.DataDir = "foo"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.DataDir)
			},
		},
		{
			msg:       "data_dir should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *serverConfig) {
				c.DataDir = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.DataDir)
			},
		},
		{
			msg: "data_dir specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.DataDir = "foo"
			},
			cliInput: func(c *serverConfig) {
				c.DataDir = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.DataDir)
			},
		},
		{
			msg: "jwt_issuer should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.JWTIssuer = "ISSUER"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "ISSUER", c.Server.JWTIssuer)
			},
		},
		{
			msg: "log_file should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.LogFile = "foo"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.LogFile)
			},
		},
		{
			msg:       "log_file should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *serverConfig) {
				c.LogFile = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.LogFile)
			},
		},
		{
			msg: "log_file specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.LogFile = "foo"
			},
			cliInput: func(c *serverConfig) {
				c.LogFile = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.LogFile)
			},
		},
		{
			msg:       "log_format should default to log.DefaultFormat if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, log.DefaultFormat, c.Server.LogFormat)
			},
		},
		{
			msg: "log_format should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.LogFormat = "JSON"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "JSON", c.Server.LogFormat)
			},
		},
		{
			msg:       "log_format should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *serverConfig) {
				c.LogFormat = "JSON"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "JSON", c.Server.LogFormat)
			},
		},
		{
			msg: "log_format specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.LogFormat = "TEXT"
			},
			cliInput: func(c *serverConfig) {
				c.LogFormat = "JSON"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "JSON", c.Server.LogFormat)
			},
		},
		{
			msg:       "log_level should default to INFO if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "INFO", c.Server.LogLevel)
			},
		},
		{
			msg: "log_level should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.LogLevel = "DEBUG"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "DEBUG", c.Server.LogLevel)
			},
		},
		{
			msg:       "log_level should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *serverConfig) {
				c.LogLevel = "DEBUG"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "DEBUG", c.Server.LogLevel)
			},
		},
		{
			msg: "log_level specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.LogLevel = "WARN"
			},
			cliInput: func(c *serverConfig) {
				c.LogLevel = "DEBUG"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "DEBUG", c.Server.LogLevel)
			},
		},
		{
			msg: "socket_path should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.SocketPath = "foo"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.SocketPath)
			},
		},
		{
			msg:       "socket_path should be configuable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *serverConfig) {
				c.SocketPath = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.SocketPath)
			},
		},
		{
			msg: "socket_path specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.SocketPath = "foo"
			},
			cliInput: func(c *serverConfig) {
				c.SocketPath = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.SocketPath)
			},
		},
		{
			msg:       "deprecated registration_uds_path should default to empty if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Empty(t, c.Server.DeprecatedRegistrationUDSPath)
			},
		},
		{
			msg: "deprecated registration_uds_path should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.DeprecatedRegistrationUDSPath = "foo"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.DeprecatedRegistrationUDSPath)
			},
		},
		{
			msg:       "deprecated registration_uds_path should be configuable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *serverConfig) {
				c.DeprecatedRegistrationUDSPath = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.DeprecatedRegistrationUDSPath)
			},
		},
		{
			msg: "deprecated registration_uds_path specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.DeprecatedRegistrationUDSPath = "foo"
			},
			cliInput: func(c *serverConfig) {
				c.DeprecatedRegistrationUDSPath = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.DeprecatedRegistrationUDSPath)
			},
		},
		{
			msg: "default_svid_ttl should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.DefaultSVIDTTL = "1h"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "1h", c.Server.DefaultSVIDTTL)
			},
		},
		{
			msg:       "trust_domain should not have a default value",
			fileInput: func(c *Config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "", c.Server.TrustDomain)
			},
		},
		{
			msg: "trust_domain should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.TrustDomain = "foo"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.TrustDomain)
			},
		},
		{
			// TODO: should it really?
			msg:       "trust_domain should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *serverConfig) {
				c.TrustDomain = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.TrustDomain)
			},
		},
		{
			msg: "trust_domain specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.TrustDomain = "foo"
			},
			cliInput: func(c *serverConfig) {
				c.TrustDomain = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.TrustDomain)
			},
		},
	}

	for _, testCase := range cases {
		testCase := testCase

		fileInput := &Config{Server: &serverConfig{}}
		cliInput := &serverConfig{}

		testCase.fileInput(fileInput)
		testCase.cliInput(cliInput)

		t.Run(testCase.msg, func(t *testing.T) {
			i, err := mergeInput(fileInput, cliInput)
			require.NoError(t, err)

			testCase.test(t, i)
		})
	}
}

func TestNewServerConfig(t *testing.T) {
	cases := []struct {
		msg         string
		expectError bool
		input       func(*Config)
		logOptions  func(t *testing.T) []log.Option
		test        func(*testing.T, *server.Config)
	}{
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
			msg: "deprecated registration_uds_path should be correctly configured",
			input: func(c *Config) {
				c.Server.DeprecatedRegistrationUDSPath = "foo"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "foo", c.BindUDSAddress.Name)
				require.Equal(t, "unix", c.BindUDSAddress.Net)
			},
		},
		{
			msg: "socket_path should be correctly configured",
			input: func(c *Config) {
				c.Server.SocketPath = "foo"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "foo", c.BindUDSAddress.Name)
				require.Equal(t, "unix", c.BindUDSAddress.Net)
			},
		},
		{
			msg: "default socket_path should be used if neither socket_path or the deprecated registration_uds_path is set",
			input: func(c *Config) {
				c.Server.DeprecatedRegistrationUDSPath = ""
				c.Server.SocketPath = ""
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, defaultSocketPath, c.BindUDSAddress.Name)
				require.Equal(t, "unix", c.BindUDSAddress.Net)
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
				require.Equal(t, &logrus.TextFormatter{}, l.Formatter)
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
				require.Equal(t, &logrus.TextFormatter{}, l.Formatter)
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
						"domain1.test": {
							BundleEndpoint: federatesWithBundleEndpointConfig{
								Address:   "192.168.1.1",
								Port:      1337,
								SpiffeID:  "spiffe://domain1.test/bundle/endpoint",
								UseWebPKI: false,
							},
						},
						"domain2.test": {
							BundleEndpoint: federatesWithBundleEndpointConfig{
								Address:   "192.168.1.1",
								Port:      1337,
								UseWebPKI: true,
							},
						},
					},
				}
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, map[spiffeid.TrustDomain]bundleClient.TrustDomainConfig{
					spiffeid.RequireTrustDomainFromString("domain1.test"): {
						EndpointAddress:  "192.168.1.1:1337",
						EndpointSpiffeID: spiffeid.RequireFromString("spiffe://domain1.test/bundle/endpoint"),
						UseWebPKI:        false,
					},
					spiffeid.RequireTrustDomainFromString("domain2.test"): {
						EndpointAddress: "192.168.1.1:1337",
						UseWebPKI:       true,
					},
				}, c.Federation.FederatesWith)
			},
		},
		{
			msg:         "bundle federates with section uses Web PKI and SpiffeID",
			expectError: true,
			input: func(c *Config) {
				c.Server.Federation = &federationConfig{
					FederatesWith: map[string]federatesWithConfig{
						"domain1.test": {
							BundleEndpoint: federatesWithBundleEndpointConfig{
								Address:   "192.168.1.1",
								SpiffeID:  "spiffe://domain1.test/bundle/endpoint",
								Port:      1337,
								UseWebPKI: true,
							},
						},
					},
				}
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "default_svid_ttl is correctly parsed",
			input: func(c *Config) {
				c.Server.DefaultSVIDTTL = "1m"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, time.Minute, c.SVIDTTL)
			},
		},
		{
			msg:         "invalid default_svid_ttl returns an error",
			expectError: true,
			input: func(c *Config) {
				c.Server.DefaultSVIDTTL = "b"
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
				require.Equal(t, defaultCASubject, c.CASubject)
			},
		},
		{
			msg: "ca_subject is defaulted when set but empty",
			input: func(c *Config) {
				c.Server.CASubject = &caSubjectConfig{}
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, defaultCASubject, c.CASubject)
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
			logOptions: func(t *testing.T) []log.Option {
				return []log.Option{
					func(logger *log.Logger) error {
						logger.SetOutput(io.Discard)
						hook := test.NewLocal(logger.Logger)
						t.Cleanup(func() {
							spiretest.AssertLogs(t, hook.AllEntries(), []spiretest.LogEntry{
								{
									Data:  map[string]interface{}{"trust_domain": strings.Repeat("a", 256)},
									Level: logrus.WarnLevel,
									Message: "Configured trust domain name should be less than 255 characters to be " +
										"SPIFFE compliant; a longer trust domain name may impact interoperability",
								},
							})
						})
						return nil
					},
				}
			},
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
	}

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

	c.Plugins = &catalog.HCLPluginConfigMap{}

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
			name: "both socket_path and registration_uds_path cannot be configured",
			applyConf: func(c *Config) {
				c.Server.SocketPath = "foo"
				c.Server.DeprecatedRegistrationUDSPath = "bar"
			},
			expectedErr: "socket_path and the deprecated registration_uds_path are mutually exclusive",
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
			name: "if FederatesWith is used, federation.bundle_endpoint.address must be configured",
			applyConf: func(c *Config) {
				federatesWith := make(map[string]federatesWithConfig)
				federatesWith["domain.test"] = federatesWithConfig{}
				c.Server.Federation = &federationConfig{
					FederatesWith: federatesWith,
				}
			},
			expectedErr: "federation.federates_with[\"domain.test\"].bundle_endpoint.address must be configured",
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
		{
			msg:      "in nested federates_with block",
			confFile: "server_bad_nested_federates_with_block.conf",
			expectedLogEntries: []logEntry{
				{
					section: `federates_with "test1"`,
					keys:    "unknown_option1,unknown_option2",
				},
				{
					section: `federates_with "test2"`,
					keys:    "unknown_option1,unknown_option2",
				},
			},
		},
		// TODO: Re-enable unused key detection for telemetry. See
		// https://github.com/spiffe/spire/issues/1101 for more information
		//
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
			spiretest.AssertLogsAnyOrder(t, hook.AllEntries(), logEntries)
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

	logOptions := []log.Option{
		log.WithLevel("DEBUG"),
		log.WithFormat(log.JSONFormat),
		log.WithOutputFile(fd.Name()),
	}

	agentConfig, err := NewServerConfig(defaultValidConfig(), logOptions, false)
	require.NoError(t, err)

	logger := agentConfig.Log.(*log.Logger).Logger

	// defaultConfig() sets level to info,  which should override DEBUG set above
	require.Equal(t, logrus.InfoLevel, logger.Level)

	// JSON Formatter and output file should be set from above
	require.IsType(t, &logrus.JSONFormatter{}, logger.Formatter)
	require.Equal(t, fd.Name(), logger.Out.(*os.File).Name())
}

func TestHasExpectedTTLs(t *testing.T) {
	cases := []struct {
		msg             string
		caTTL           time.Duration
		svidTTL         time.Duration
		hasExpectedTTLs bool
	}{
		// ca_ttl isn't less than default_svid_ttl * 6
		{
			msg:             "Both values are default values",
			caTTL:           0,
			svidTTL:         0,
			hasExpectedTTLs: true,
		},
		{
			msg:             "ca_ttl is 7h and default_svid_ttl is default value 1h",
			caTTL:           time.Hour * 7,
			svidTTL:         0,
			hasExpectedTTLs: true,
		},
		{
			msg:             "ca_ttl is default value 24h and default_svid_ttl is 3h",
			caTTL:           0,
			svidTTL:         time.Hour * 3,
			hasExpectedTTLs: true,
		},
		{
			msg:             "ca_ttl is 70h and default_svid_ttl is 10h",
			caTTL:           time.Hour * 70,
			svidTTL:         time.Hour * 10,
			hasExpectedTTLs: true,
		},
		// ca_ttl is less than default_svid_ttl * 6
		{
			msg:             "ca_ttl is 5h and default_svid_ttl is default value 1h",
			caTTL:           time.Hour * 5,
			svidTTL:         0,
			hasExpectedTTLs: false,
		},
		{
			msg:             "ca_ttl is default value 24h and default_svid_ttl is 5h",
			caTTL:           0,
			svidTTL:         time.Hour * 5,
			hasExpectedTTLs: false,
		},
		{
			msg:             "ca_ttl is 50h and default_svid_ttl is 10h",
			caTTL:           time.Hour * 50,
			svidTTL:         time.Hour * 10,
			hasExpectedTTLs: false,
		},
	}

	for _, testCase := range cases {
		testCase := testCase

		t.Run(testCase.msg, func(t *testing.T) {
			require.Equal(t, testCase.hasExpectedTTLs, hasExpectedTTLs(testCase.caTTL, testCase.svidTTL))
		})
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
