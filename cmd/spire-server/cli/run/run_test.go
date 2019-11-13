package run

import (
	"bytes"
	"testing"
	"time"

	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/pkg/server"
	"github.com/spiffe/spire/proto/spire/server/keymanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigGood(t *testing.T) {
	c, err := parseFile("../../../../test/fixture/config/server_good.conf")
	require.NoError(t, err)

	// Check for server configurations
	assert.Equal(t, c.Server.BindAddress, "127.0.0.1")
	assert.Equal(t, c.Server.BindPort, 8081)
	assert.Equal(t, c.Server.RegistrationUDSPath, "/tmp/server.sock")
	assert.Equal(t, c.Server.TrustDomain, "example.org")
	assert.Equal(t, c.Server.LogLevel, "INFO")
	assert.Equal(t, c.Server.Experimental.AllowAgentlessNodeAttestors, true)

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
	c, err := parseFlags([]string{
		"-bindAddress=127.0.0.1",
		"-registrationUDSPath=/tmp/flag.sock",
		"-trustDomain=example.org",
		"-logLevel=INFO",
	})
	require.NoError(t, err)
	assert.Equal(t, c.BindAddress, "127.0.0.1")
	assert.Equal(t, c.RegistrationUDSPath, "/tmp/flag.sock")
	assert.Equal(t, c.TrustDomain, "example.org")
	assert.Equal(t, c.LogLevel, "INFO")
}

func TestMergeInput(t *testing.T) {
	cases := []struct {
		msg       string
		fileInput func(*config)
		cliInput  func(*serverConfig)
		test      func(*testing.T, *config)
	}{
		{
			msg:       "bind_address should default to 0.0.0.0 if not set",
			fileInput: func(c *config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "0.0.0.0", c.Server.BindAddress)
			},
		},
		{
			msg: "bind_address should be configurable by file",
			fileInput: func(c *config) {
				c.Server.BindAddress = "10.0.0.1"
			},
			cliInput: func(c *serverConfig) {
				c.BindAddress = ""
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "10.0.0.1", c.Server.BindAddress)
			},
		},
		{
			msg: "bind_address should be configurable by CLI flag",
			fileInput: func(c *config) {
				c.Server.BindAddress = ""
			},
			cliInput: func(c *serverConfig) {
				c.BindAddress = "10.0.0.1"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "10.0.0.1", c.Server.BindAddress)
			},
		},
		{
			msg: "bind_address specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Server.BindAddress = "10.0.0.1"
			},
			cliInput: func(c *serverConfig) {
				c.BindAddress = "10.0.0.2"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "10.0.0.2", c.Server.BindAddress)
			},
		},
		{
			msg:       "bind_port should default to 8081 if not set",
			fileInput: func(c *config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, 8081, c.Server.BindPort)
			},
		},
		{
			msg: "bind_port should be configurable by file",
			fileInput: func(c *config) {
				c.Server.BindPort = 1337
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, 1337, c.Server.BindPort)
			},
		},
		{
			msg:       "bind_port should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *serverConfig) {
				c.BindPort = 1337
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, 1337, c.Server.BindPort)
			},
		},
		{
			msg: "bind_port specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Server.BindPort = 1336
			},
			cliInput: func(c *serverConfig) {
				c.BindPort = 1337
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, 1337, c.Server.BindPort)
			},
		},
		{
			msg: "ca_key_type should be configurable by file",
			fileInput: func(c *config) {
				c.Server.CAKeyType = "rsa-2048"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "rsa-2048", c.Server.CAKeyType)
			},
		},
		{
			msg: "ca_subject should be configurable by file",
			fileInput: func(c *config) {
				c.Server.CASubject = &caSubjectConfig{
					Country:      []string{"test-country"},
					Organization: []string{"test-org"},
					CommonName:   "test-cn",
				}
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, []string{"test-country"}, c.Server.CASubject.Country)
				require.Equal(t, []string{"test-org"}, c.Server.CASubject.Organization)
				require.Equal(t, "test-cn", c.Server.CASubject.CommonName)
			},
		},
		{
			msg: "ca_ttl should be configurable by file",
			fileInput: func(c *config) {
				c.Server.CATTL = "1h"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "1h", c.Server.CATTL)
			},
		},
		{
			msg: "data_dir should be configurable by file",
			fileInput: func(c *config) {
				c.Server.DataDir = "foo"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Server.DataDir)
			},
		},
		{
			msg:       "data_dir should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *serverConfig) {
				c.DataDir = "foo"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Server.DataDir)
			},
		},
		{
			msg: "data_dir specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Server.DataDir = "foo"
			},
			cliInput: func(c *serverConfig) {
				c.DataDir = "bar"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "bar", c.Server.DataDir)
			},
		},
		{
			msg: "jwt_issuer should be configurable by file",
			fileInput: func(c *config) {
				c.Server.JWTIssuer = "ISSUER"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "ISSUER", c.Server.JWTIssuer)
			},
		},
		{
			msg: "log_file should be configurable by file",
			fileInput: func(c *config) {
				c.Server.LogFile = "foo"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Server.LogFile)
			},
		},
		{
			msg:       "log_file should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *serverConfig) {
				c.LogFile = "foo"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Server.LogFile)
			},
		},
		{
			msg: "log_file specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Server.LogFile = "foo"
			},
			cliInput: func(c *serverConfig) {
				c.LogFile = "bar"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "bar", c.Server.LogFile)
			},
		},
		{
			msg:       "log_format should default to log.DefaultFormat if not set",
			fileInput: func(c *config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, log.DefaultFormat, c.Server.LogFormat)
			},
		},
		{
			msg: "log_format should be configurable by file",
			fileInput: func(c *config) {
				c.Server.LogFormat = "JSON"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "JSON", c.Server.LogFormat)
			},
		},
		{
			msg:       "log_format should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *serverConfig) {
				c.LogFormat = "JSON"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "JSON", c.Server.LogFormat)
			},
		},
		{
			msg: "log_format specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Server.LogFormat = "TEXT"
			},
			cliInput: func(c *serverConfig) {
				c.LogFormat = "JSON"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "JSON", c.Server.LogFormat)
			},
		},
		{
			msg:       "log_level should default to INFO if not set",
			fileInput: func(c *config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "INFO", c.Server.LogLevel)
			},
		},
		{
			msg: "log_level should be configurable by file",
			fileInput: func(c *config) {
				c.Server.LogLevel = "DEBUG"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "DEBUG", c.Server.LogLevel)
			},
		},
		{
			msg:       "log_level should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *serverConfig) {
				c.LogLevel = "DEBUG"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "DEBUG", c.Server.LogLevel)
			},
		},
		{
			msg: "log_level specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Server.LogLevel = "WARN"
			},
			cliInput: func(c *serverConfig) {
				c.LogLevel = "DEBUG"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "DEBUG", c.Server.LogLevel)
			},
		},
		{
			msg:       "registration_uds_path should default to /tmp/spire-registration.sock if not set",
			fileInput: func(c *config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "/tmp/spire-registration.sock", c.Server.RegistrationUDSPath)
			},
		},
		{
			msg: "registration_uds_path should be configurable by file",
			fileInput: func(c *config) {
				c.Server.RegistrationUDSPath = "foo"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Server.RegistrationUDSPath)
			},
		},
		{
			msg:       "registration_uds_path should be configuable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *serverConfig) {
				c.RegistrationUDSPath = "foo"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Server.RegistrationUDSPath)
			},
		},
		{
			msg: "registration_uds_path specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Server.RegistrationUDSPath = "foo"
			},
			cliInput: func(c *serverConfig) {
				c.RegistrationUDSPath = "bar"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "bar", c.Server.RegistrationUDSPath)
			},
		},
		{
			msg: "default_svid_ttl should be configurable by file",
			fileInput: func(c *config) {
				c.Server.DefaultSVIDTTL = "1h"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "1h", c.Server.DefaultSVIDTTL)
			},
		},
		{
			msg:       "trust_domain should not have a default value",
			fileInput: func(c *config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "", c.Server.TrustDomain)
			},
		},
		{
			msg: "trust_domain should be configurable by file",
			fileInput: func(c *config) {
				c.Server.TrustDomain = "foo"
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Server.TrustDomain)
			},
		},
		{
			// TODO: should it really?
			msg:       "trust_domain should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *serverConfig) {
				c.TrustDomain = "foo"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Server.TrustDomain)
			},
		},
		{
			msg: "trust_domain specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Server.TrustDomain = "foo"
			},
			cliInput: func(c *serverConfig) {
				c.TrustDomain = "bar"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "bar", c.Server.TrustDomain)
			},
		},
		{
			msg:       "upstream_bundle should be nil if not set",
			fileInput: func(c *config) {},
			cliInput:  func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.Nil(t, c.Server.UpstreamBundle)
			},
		},
		{
			msg: "upstream_bundle should be configurable by file",
			fileInput: func(c *config) {
				value := true
				c.Server.UpstreamBundle = &value
			},
			cliInput: func(c *serverConfig) {},
			test: func(t *testing.T, c *config) {
				require.NotNil(t, c.Server.UpstreamBundle)
				require.Equal(t, true, *c.Server.UpstreamBundle)
			},
		},
		{
			msg:       "upstream_bundle should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *serverConfig) {
				value := true
				c.UpstreamBundle = &value
			},
			test: func(t *testing.T, c *config) {
				require.NotNil(t, c.Server.UpstreamBundle)
				require.Equal(t, true, *c.Server.UpstreamBundle)
			},
		},
		//{
		//      // TODO: This is currently unsupported
		//	msg: "upstream_bundle specified by CLI flag should take precedence over file",
		//	fileInput: func(c *config) {
		//		c.Server.UpstreamBundle = true
		//	},
		//	cliInput: func(c *serverConfig) {
		//		c.UpstreamBundle = false
		//	},
		//	test: func(t *testing.T, c *config) {
		//		require.Equal(t, false, c.Server.UpstreamBundle)
		//	},
		//},
	}

	for _, testCase := range cases {
		fileInput := &config{Server: &serverConfig{}}
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
		input       func(*config)
		test        func(*testing.T, *server.Config)
	}{
		{
			msg: "bind_address and bind_port should be correctly parsed",
			input: func(c *config) {
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
			input: func(c *config) {
				c.Server.BindAddress = "this-is-not-an-ip-address"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "registration_uds_path should be correctly configured",
			input: func(c *config) {
				c.Server.RegistrationUDSPath = "foo"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "foo", c.BindUDSAddress.Name)
				require.Equal(t, "unix", c.BindUDSAddress.Net)
			},
		},
		{
			msg: "data_dir should be correctly configured",
			input: func(c *config) {
				c.Server.DataDir = "foo"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "foo", c.DataDir)
			},
		},
		{
			msg: "trust_domain should be correctly parsed",
			input: func(c *config) {
				c.Server.TrustDomain = "foo"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "spiffe://foo", c.TrustDomain.String())
			},
		},
		{
			msg:         "invalid trust_domain should return an error",
			expectError: true,
			input: func(c *config) {
				c.Server.TrustDomain = "i'm invalid"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "jwt_issuer is correctly configured",
			input: func(c *config) {
				c.Server.JWTIssuer = "ISSUER"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, "ISSUER", c.JWTIssuer)
			},
		},
		{
			msg: "logger gets set correctly",
			input: func(c *config) {
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
			input: func(c *config) {
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
			input: func(c *config) {
				c.Server.LogLevel = "not-a-valid-level"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:         "invalid log_format returns an error",
			expectError: true,
			input: func(c *config) {
				c.Server.LogFormat = "not-a-valid-format"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "upstream_bundle is configured correctly",
			input: func(c *config) {
				value := true
				c.Server.UpstreamBundle = &value
			},
			test: func(t *testing.T, c *server.Config) {
				require.True(t, c.UpstreamBundle)
			},
		},
		{
			msg: "allow_agentless_node_attestors is configured correctly",
			input: func(c *config) {
				c.Server.Experimental.AllowAgentlessNodeAttestors = true
			},
			test: func(t *testing.T, c *server.Config) {
				require.True(t, c.Experimental.AllowAgentlessNodeAttestors)
			},
		},
		{
			msg: "bundle endpoint is parsed and configured correctly",
			input: func(c *config) {
				c.Server.Experimental.BundleEndpointEnabled = true
				c.Server.Experimental.BundleEndpointAddress = "192.168.1.1"
				c.Server.Experimental.BundleEndpointPort = 1337
			},
			test: func(t *testing.T, c *server.Config) {
				require.True(t, c.Experimental.BundleEndpointEnabled)
				require.Equal(t, "192.168.1.1", c.Experimental.BundleEndpointAddress.IP.String())
				require.Equal(t, 1337, c.Experimental.BundleEndpointAddress.Port)
			},
		},
		{
			msg: "deprecated svid_ttl is correctly parsed",
			input: func(c *config) {
				c.Server.DeprecatedSVIDTTL = "1m"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, time.Minute, c.DefaultSVIDTTL)
			},
		},
		{
			msg:         "invalid deprecated svid_ttl returns an error",
			expectError: true,
			input: func(c *config) {
				c.Server.DeprecatedSVIDTTL = "b"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "default_svid_ttl is correctly parsed",
			input: func(c *config) {
				c.Server.DefaultSVIDTTL = "1m"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, time.Minute, c.DefaultSVIDTTL)
			},
		},
		{
			msg:         "invalid default_svid_ttl returns an error",
			expectError: true,
			input: func(c *config) {
				c.Server.DefaultSVIDTTL = "b"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "default_svid_ttl preferred over svid_ttl",
			input: func(c *config) {
				c.Server.DeprecatedSVIDTTL = "2m"
				c.Server.DefaultSVIDTTL = "1m"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, time.Minute, c.DefaultSVIDTTL)
			},
		},
		{
			msg: "rsa-2048 ca_key_type is correctly parsed",
			input: func(c *config) {
				c.Server.CAKeyType = "rsa-2048"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.KeyType_RSA_2048, c.CAKeyType)
			},
		},
		{
			msg: "rsa-4096 ca_key_type is correctly parsed",
			input: func(c *config) {
				c.Server.CAKeyType = "rsa-4096"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.KeyType_RSA_4096, c.CAKeyType)
			},
		},
		{
			msg: "ec-p256 ca_key_type is correctly parsed",
			input: func(c *config) {
				c.Server.CAKeyType = "ec-p256"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.KeyType_EC_P256, c.CAKeyType)
			},
		},
		{
			msg: "ec-p384 ca_key_type is correctly parsed",
			input: func(c *config) {
				c.Server.CAKeyType = "ec-p384"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, keymanager.KeyType_EC_P384, c.CAKeyType)
			},
		},
		{
			msg:         "unsupported ca_key_type is rejected",
			expectError: true,
			input: func(c *config) {
				c.Server.CAKeyType = "rsa-1024"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "ca_ttl is correctly parsed",
			input: func(c *config) {
				c.Server.CATTL = "1h"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, time.Hour, c.CATTL)
			},
		},
		{
			msg:         "invalid ca_ttl returns an error",
			expectError: true,
			input: func(c *config) {
				c.Server.CATTL = "b"
			},
			test: func(t *testing.T, c *server.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "ca_subject is configured correctly",
			input: func(c *config) {
				c.Server.CASubject = &caSubjectConfig{
					Organization: []string{"foo"},
					Country:      []string{"us"},
					CommonName:   "bar",
				}
			},
			test: func(t *testing.T, c *server.Config) {
				require.Equal(t, []string{"foo"}, c.CASubject.Organization)
				require.Equal(t, []string{"us"}, c.CASubject.Country)
				require.Equal(t, "bar", c.CASubject.CommonName)
			},
		},
	}

	for _, testCase := range cases {
		input := defaultValidConfig()

		testCase.input(input)

		t.Run(testCase.msg, func(t *testing.T) {
			sc, err := newServerConfig(input)
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
func defaultValidConfig() *config {
	c := defaultConfig()

	c.Server.DataDir = "."
	c.Server.TrustDomain = "example.org"

	c.Plugins = &catalog.HCLPluginConfigMap{}

	return c
}
