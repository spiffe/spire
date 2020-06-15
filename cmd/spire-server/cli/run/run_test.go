package run

import (
	"bytes"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
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
	assert.Equal(t, c.Server.RegistrationUDSPath, "/tmp/server.sock")
	assert.Equal(t, c.Server.TrustDomain, "example.org")
	assert.Equal(t, c.Server.LogLevel, "INFO")
	assert.Equal(t, c.Server.Experimental.AllowAgentlessNodeAttestors, true)
	assert.Equal(t, len(c.Server.FederateWith), 2)
	assert.Equal(t, c.Server.FederateWith["spiffe://domain1.test"].BundleEndpoint.Address, "1.2.3.4")
	assert.True(t, c.Server.FederateWith["spiffe://domain1.test"].BundleEndpoint.UseWebPKI)
	assert.Equal(t, c.Server.FederateWith["spiffe://domain2.test"].BundleEndpoint.Address, "5.6.7.8")
	assert.Equal(t, c.Server.FederateWith["spiffe://domain2.test"].BundleEndpoint.SpiffeID, "spiffe://domain2.test/bundle-provider")

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
		"-registrationUDSPath=/tmp/flag.sock",
		"-trustDomain=example.org",
		"-logLevel=INFO",
	}, os.Stderr)
	require.NoError(t, err)
	assert.Equal(t, c.BindAddress, "127.0.0.1")
	assert.Equal(t, c.RegistrationUDSPath, "/tmp/flag.sock")
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
			msg:       "registration_uds_path should default to /tmp/spire-registration.sock if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "/tmp/spire-registration.sock", c.Server.RegistrationUDSPath)
			},
		},
		{
			msg: "registration_uds_path should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.RegistrationUDSPath = "foo"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.RegistrationUDSPath)
			},
		},
		{
			msg:       "registration_uds_path should be configuable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *serverConfig) {
				c.RegistrationUDSPath = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Server.RegistrationUDSPath)
			},
		},
		{
			msg: "registration_uds_path specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Server.RegistrationUDSPath = "foo"
			},
			cliInput: func(c *serverConfig) {
				c.RegistrationUDSPath = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Server.RegistrationUDSPath)
			},
		},
		{
			msg: "deprecated svid_ttl should be configurable by file",
			fileInput: func(c *Config) {
				c.Server.DeprecatedSVIDTTL = "1h"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "1h", c.Server.DeprecatedSVIDTTL)
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
		{
			msg:       "upstream_bundle should be nil if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Nil(t, c.Server.UpstreamBundle)
			},
		},
		{
			msg: "upstream_bundle should be configurable by file",
			fileInput: func(c *Config) {
				value := true
				c.Server.UpstreamBundle = &value
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *Config) {
				require.NotNil(t, c.Server.UpstreamBundle)
				require.Equal(t, true, *c.Server.UpstreamBundle)
			},
		},
		{
			msg:       "upstream_bundle should be configurable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *serverConfig) {
				value := true
				c.UpstreamBundle = &value
			},
			test: func(t *testing.T, c *Config) {
				require.NotNil(t, c.Server.UpstreamBundle)
				require.Equal(t, true, *c.Server.UpstreamBundle)
			},
		},
		//{
		//      // TODO: This is currently unsupported
		//	msg: "upstream_bundle specified by CLI flag should take precedence over file",
		//	fileInput: func(c *Config) {
		//		c.Server.UpstreamBundle = true
		//	},
		//	cliInput: func(c *serverConfig) {
		//		c.UpstreamBundle = false
		//	},
		//	test: func(t *testing.T, c *Config) {
		//		require.Equal(t, false, c.Server.UpstreamBundle)
		//	},
		//},
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
			msg: "registration_uds_path should be correctly configured",
			input: func(c *Config) {
				c.Server.RegistrationUDSPath = "foo"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "foo", c.BindUDSAddress.Name)
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
				require.Equal(t, "spiffe://foo", c.TrustDomain.String())
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
			msg: "upstream_bundle is configured correctly",
			input: func(c *Config) {
				value := false
				c.Server.UpstreamBundle = &value
			},
			test: func(t *testing.T, c *server.Config) {
				require.False(t, c.UpstreamBundle)
			},
		},
		{
			msg:   "upstream_bundle default value must be 'true'",
			input: func(c *Config) {},
			test: func(t *testing.T, c *server.Config) {
				require.True(t, c.UpstreamBundle)
			},
		},
		{
			msg: "allow_agentless_node_attestors is configured correctly",
			input: func(c *Config) {
				c.Server.Experimental.AllowAgentlessNodeAttestors = true
			},
			test: func(t *testing.T, c *server.Config) {
				require.True(t, c.Experimental.AllowAgentlessNodeAttestors)
			},
		},
		{
			msg: "bundle endpoint is parsed and configured correctly",
			input: func(c *Config) {
				c.Server.BundleEndpoint.Enabled = true
				c.Server.BundleEndpoint.Address = "192.168.1.1"
				c.Server.BundleEndpoint.Port = 1337
			},
			test: func(t *testing.T, c *server.Config) {
				require.True(t, c.BundleEndpoint.Enabled)
				require.Equal(t, "192.168.1.1", c.BundleEndpoint.Address.IP.String())
				require.Equal(t, 1337, c.BundleEndpoint.Address.Port)
			},
		},
		{
			msg: "bundle federates with section is parsed and configured correctly",
			input: func(c *Config) {
				c.Server.FederateWith = map[string]federateWithConfig{
					"spiffe://domain1.test": {
						BundleEndpoint: federateWithBundleEndpointConfig{
							Address:   "192.168.1.1",
							Port:      1337,
							SpiffeID:  "spiffe://domain1.test/bundle/endpoint",
							UseWebPKI: false,
						},
					},
					"spiffe://domain2.test": {
						BundleEndpoint: federateWithBundleEndpointConfig{
							Address:   "192.168.1.1",
							SpiffeID:  "THIS SHOULD BE IGNORED",
							Port:      1337,
							UseWebPKI: true,
						},
					},
				}
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, map[string]bundleClient.TrustDomainConfig{
					"spiffe://domain1.test": {
						EndpointAddress:  "192.168.1.1:1337",
						EndpointSpiffeID: "spiffe://domain1.test/bundle/endpoint",
						UseWebPKI:        false,
					},
					"spiffe://domain2.test": {
						EndpointAddress: "192.168.1.1:1337",
						UseWebPKI:       true,
					},
				}, c.FederateWith)
			},
		},
		{
			msg:         "using deprecated svid_ttl returns an error",
			expectError: true,
			input: func(c *Config) {
				c.Server.DeprecatedSVIDTTL = "1m"
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
			msg: "rsa-2048 ca_key_type is correctly parsed",
			input: func(c *Config) {
				c.Server.CAKeyType = "rsa-2048"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.KeyType_RSA_2048, c.CAKeyType)
			},
		},
		{
			msg: "rsa-4096 ca_key_type is correctly parsed",
			input: func(c *Config) {
				c.Server.CAKeyType = "rsa-4096"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.KeyType_RSA_4096, c.CAKeyType)
			},
		},
		{
			msg: "ec-p256 ca_key_type is correctly parsed",
			input: func(c *Config) {
				c.Server.CAKeyType = "ec-p256"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.KeyType_EC_P256, c.CAKeyType)
			},
		},
		{
			msg: "ec-p384 ca_key_type is correctly parsed",
			input: func(c *Config) {
				c.Server.CAKeyType = "ec-p384"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.KeyType_EC_P384, c.CAKeyType)
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
	}

	for _, testCase := range cases {
		testCase := testCase

		input := defaultValidConfig()

		testCase.input(input)

		t.Run(testCase.msg, func(t *testing.T) {
			sc, err := NewServerConfig(input, []log.Option{})
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
			name:        "registration_uds_path must be configured",
			applyConf:   func(c *Config) { c.Server.RegistrationUDSPath = "" },
			expectedErr: "registration_uds_path must be configured",
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
			name: "if ACME is used, bundle_endpoint.acme.domain_name must be configured",
			applyConf: func(c *Config) {
				c.Server.BundleEndpoint.ACME = &bundleEndpointACMEConfig{}
			},
			expectedErr: "bundle_endpoint.acme.domain_name must be configured",
		},
		{
			name: "if ACME is used, bundle_endpoint.acme.email must be configured",
			applyConf: func(c *Config) {
				c.Server.BundleEndpoint.ACME = &bundleEndpointACMEConfig{
					DomainName: "domain-name",
				}
			},
			expectedErr: "bundle_endpoint.acme.email must be configured",
		},
		{
			name: "if FederateWith is used, bundle_endpoint.address must be configured",
			applyConf: func(c *Config) {
				federatesWith := make(map[string]federateWithConfig)
				federatesWith["spiffe://domain.test"] = federateWithConfig{}
				c.Server.FederateWith = federatesWith
			},
			expectedErr: "spiffe://domain.test bundle_endpoint.address must be configured",
		},
		{
			name:        "deprecated configurable `svid_ttl` must not be set",
			applyConf:   func(c *Config) { c.Server.DeprecatedSVIDTTL = "1h" },
			expectedErr: `the "svid_ttl" configurable has been deprecated and renamed to "default_svid_ttl"; please update your configuration`,
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
	cases := []struct {
		msg            string
		testFilePath   string
		expectedLogMsg string
	}{
		{
			msg:            "in root block",
			testFilePath:   fmt.Sprintf("%v/server_and_agent_bad_root_block.conf", testFileDir),
			expectedLogMsg: "Detected unknown top-level config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		},
		{
			msg:            "in server block",
			testFilePath:   fmt.Sprintf("%v/server_bad_server_block.conf", testFileDir),
			expectedLogMsg: "Detected unknown server config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		},
		{
			msg:            "in nested ca_subject block",
			testFilePath:   fmt.Sprintf("%v/server_bad_nested_ca_subject_block.conf", testFileDir),
			expectedLogMsg: "Detected unknown CA Subject config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		},
		// TODO: Re-enable unused key detection for experimental config. See
		// https://github.com/spiffe/spire/issues/1101 for more information
		//
		//{
		//	msg:            "in nested experimental block",
		//	testFilePath:   fmt.Sprintf("%v/server_bad_nested_experimental_block.conf", testFileDir),
		//	expectedLogMsg: "Detected unknown experimental config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		//},
		{
			msg:            "in nested bundle_endpoint.acme block",
			testFilePath:   fmt.Sprintf("%v/server_bad_nested_bundle_endpoint_acme_block.conf", testFileDir),
			expectedLogMsg: "Detected unknown ACME config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		},
		{
			msg:            "in nested federate_with block",
			testFilePath:   fmt.Sprintf("%v/server_bad_nested_federates_with_block.conf", testFileDir),
			expectedLogMsg: "Detected unknown federation config options for \"test1\": [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		},
		// TODO: Re-enable unused key detection for telemetry. See
		// https://github.com/spiffe/spire/issues/1101 for more information
		//
		//{
		//	msg:            "in telemetry block",
		//	testFilePath:   fmt.Sprintf("%v/server_and_agent_bad_telemetry_block.conf", testFileDir),
		//	expectedLogMsg: "Detected unknown telemetry config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		//},
		{
			msg:            "in nested Prometheus block",
			testFilePath:   fmt.Sprintf("%v/server_and_agent_bad_nested_Prometheus_block.conf", testFileDir),
			expectedLogMsg: "Detected unknown Prometheus config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		},
		{
			msg:            "in nested DogStatsd block",
			testFilePath:   fmt.Sprintf("%v/server_and_agent_bad_nested_DogStatsd_block.conf", testFileDir),
			expectedLogMsg: "Detected unknown DogStatsd config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		},
		{
			msg:            "in nested Statsd block",
			testFilePath:   fmt.Sprintf("%v/server_and_agent_bad_nested_Statsd_block.conf", testFileDir),
			expectedLogMsg: "Detected unknown Statsd config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		},
		{
			msg:            "in nested M3 block",
			testFilePath:   fmt.Sprintf("%v/server_and_agent_bad_nested_M3_block.conf", testFileDir),
			expectedLogMsg: "Detected unknown M3 config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		},
		{
			msg:            "in nested InMem block",
			testFilePath:   fmt.Sprintf("%v/server_and_agent_bad_nested_InMem_block.conf", testFileDir),
			expectedLogMsg: "Detected unknown InMem config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		},
		{
			msg:            "in nested health_checks block",
			testFilePath:   fmt.Sprintf("%v/server_and_agent_bad_nested_health_checks_block.conf", testFileDir),
			expectedLogMsg: "Detected unknown health check config options: [\"unknown_option1\" \"unknown_option2\"]; this will be fatal in a future release.",
		},
	}

	for _, testCase := range cases {
		testCase := testCase

		c, err := ParseFile(testCase.testFilePath, false)
		require.NoError(t, err)

		log, hook := test.NewNullLogger()

		t.Run(testCase.msg, func(t *testing.T) {
			warnOnUnknownConfig(c, log)
			requireLogLine(t, hook, testCase.expectedLogMsg)

			hook.Reset()
			require.Nil(t, hook.LastEntry())
		})
	}
}

func requireLogLine(t *testing.T, h *test.Hook, expectedMsg string) {
	var currMsg string
	for _, e := range h.AllEntries() {
		currMsg = e.Message
		if currMsg == expectedMsg {
			break
		}
	}

	require.Equal(t, expectedMsg, currMsg)
}

// TestLogOptions verifies the log options given to newAgentConfig are applied, and are overridden
// by values from the config file
func TestLogOptions(t *testing.T) {
	fd, err := ioutil.TempFile("", "test")
	require.NoError(t, err)
	require.NoError(t, fd.Close())
	defer os.Remove(fd.Name())

	logOptions := []log.Option{
		log.WithLevel("DEBUG"),
		log.WithFormat(log.JSONFormat),
		log.WithOutputFile(fd.Name()),
	}

	agentConfig, err := NewServerConfig(defaultValidConfig(), logOptions)
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
