package run

import (
	"bytes"
	"path"
	"testing"

	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigGood(t *testing.T) {
	c, err := parseFile("../../../../test/fixture/config/agent_good.conf")
	require.NoError(t, err)
	assert.Equal(t, c.Agent.DataDir, ".")
	assert.Equal(t, c.Agent.LogLevel, "INFO")
	assert.Equal(t, c.Agent.ServerAddress, "127.0.0.1")
	assert.Equal(t, c.Agent.ServerPort, 8081)
	assert.Equal(t, c.Agent.SocketPath, "/tmp/agent.sock")
	assert.Equal(t, c.Agent.TrustBundlePath, "conf/agent/dummy_root_ca.crt")
	assert.Equal(t, c.Agent.TrustDomain, "example.org")

	// Check for plugins configurations
	pluginConfigs := *c.Plugins
	expectedData := "join_token = \"PLUGIN-AGENT-NOT-A-SECRET\""
	var data bytes.Buffer
	err = printer.DefaultConfig.Fprint(&data, pluginConfigs["plugin_type_agent"]["plugin_name_agent"].PluginData)
	assert.NoError(t, err)

	assert.Len(t, pluginConfigs, 1)
	assert.Len(t, pluginConfigs["plugin_type_agent"], 3)

	pluginConfig := pluginConfigs["plugin_type_agent"]["plugin_name_agent"]
	assert.Nil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), true)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginAgentChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, "./pluginAgentCmd")
	assert.Equal(t, expectedData, data.String())

	// Disabled plugin
	pluginConfig = pluginConfigs["plugin_type_agent"]["plugin_disabled"]
	assert.NotNil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), false)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginAgentChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, "./pluginAgentCmd")
	assert.Equal(t, expectedData, data.String())

	// Enabled plugin
	pluginConfig = pluginConfigs["plugin_type_agent"]["plugin_enabled"]
	assert.NotNil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), true)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginAgentChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, "./pluginAgentCmd")
	assert.Equal(t, expectedData, data.String())
}

func TestParseFlagsGood(t *testing.T) {
	c, err := parseFlags([]string{
		"-dataDir=.",
		"-logLevel=INFO",
		"-serverAddress=127.0.0.1",
		"-serverPort=8081",
		"-socketPath=/tmp/agent.sock",
		"-trustBundle=conf/agent/dummy_root_ca.crt",
		"-trustDomain=example.org",
	})
	require.NoError(t, err)
	assert.Equal(t, c.DataDir, ".")
	assert.Equal(t, c.LogLevel, "INFO")
	assert.Equal(t, c.ServerAddress, "127.0.0.1")
	assert.Equal(t, c.ServerPort, 8081)
	assert.Equal(t, c.SocketPath, "/tmp/agent.sock")
	assert.Equal(t, c.TrustBundlePath, "conf/agent/dummy_root_ca.crt")
	assert.Equal(t, c.TrustDomain, "example.org")
}

func TestMergeInput(t *testing.T) {
	cases := []struct {
		msg       string
		fileInput func(*config)
		cliInput  func(*agentConfig)
		test      func(*testing.T, *config)
	}{
		{
			msg: "data_dir should be configurable by file",
			fileInput: func(c *config) {
				c.Agent.DataDir = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.DataDir)
			},
		},
		{
			msg:       "data_dir should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *agentConfig) {
				c.DataDir = "foo"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.DataDir)
			},
		},
		{
			msg: "data_dir specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Agent.DataDir = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.DataDir = "bar"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "bar", c.Agent.DataDir)
			},
		},
		{
			msg: "enable_sds should be configurable by file",
			fileInput: func(c *config) {
				c.Agent.EnableSDS = true
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.True(t, c.Agent.EnableSDS)
			},
		},
		{
			msg:       "enable_sds should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *agentConfig) {
				c.EnableSDS = true
			},
			test: func(t *testing.T, c *config) {
				require.True(t, c.Agent.EnableSDS)
			},
		},
		//{
		//      // TODO: This is currently unsupported
		//	msg: "enable_sds specified by CLI flag should take precedence over file",
		//	fileInput: func(c *config) {
		//		c.Agent.EnableSDS = true
		//	},
		//	cliInput: func(c *agentConfig) {
		//		c.EnableSDS = false
		//	},
		//	test: func(t *testing.T, c *config) {
		//		require.False(t, c.Agent.EnableSDS)
		//	},
		//},
		{
			msg: "join_token should be configurable by file",
			fileInput: func(c *config) {
				c.Agent.JoinToken = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.JoinToken)
			},
		},
		{
			msg:       "join_token should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *agentConfig) {
				c.JoinToken = "foo"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.JoinToken)
			},
		},
		{
			msg: "join_token specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Agent.JoinToken = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.JoinToken = "bar"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "bar", c.Agent.JoinToken)
			},
		},
		{
			msg: "log_file should be configurable by file",
			fileInput: func(c *config) {
				c.Agent.LogFile = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.LogFile)
			},
		},
		{
			msg:       "log_file should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *agentConfig) {
				c.LogFile = "foo"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.LogFile)
			},
		},
		{
			msg: "log_file specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Agent.LogFile = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.LogFile = "bar"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "bar", c.Agent.LogFile)
			},
		},
		{
			msg:       "log_format should default to log.DefaultFormat if not set",
			fileInput: func(c *config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, log.DefaultFormat, c.Agent.LogFormat)
			},
		},
		{
			msg: "log_format should be configurable by file",
			fileInput: func(c *config) {
				c.Agent.LogFormat = "JSON"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "JSON", c.Agent.LogFormat)
			},
		},
		{
			msg:       "log_format should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *agentConfig) {
				c.LogFormat = "JSON"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "JSON", c.Agent.LogFormat)
			},
		},
		{
			msg: "log_format specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Agent.LogFormat = "TEXT"
			},
			cliInput: func(c *agentConfig) {
				c.LogFormat = "JSON"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "JSON", c.Agent.LogFormat)
			},
		},
		{
			msg:       "log_level should default to INFO if not set",
			fileInput: func(c *config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "INFO", c.Agent.LogLevel)
			},
		},
		{
			msg: "log_level should be configurable by file",
			fileInput: func(c *config) {
				c.Agent.LogLevel = "DEBUG"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "DEBUG", c.Agent.LogLevel)
			},
		},
		{
			msg:       "log_level should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *agentConfig) {
				c.LogLevel = "DEBUG"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "DEBUG", c.Agent.LogLevel)
			},
		},
		{
			msg: "log_level specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Agent.LogLevel = "WARN"
			},
			cliInput: func(c *agentConfig) {
				c.LogLevel = "DEBUG"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "DEBUG", c.Agent.LogLevel)
			},
		},
		{
			msg:       "server_address should not have a default value",
			fileInput: func(c *config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "", c.Agent.ServerAddress)
			},
		},
		{
			msg: "server_address should be configurable by file",
			fileInput: func(c *config) {
				c.Agent.ServerAddress = "10.0.0.1"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "10.0.0.1", c.Agent.ServerAddress)
			},
		},
		{
			msg:       "server_address should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *agentConfig) {
				c.ServerAddress = "10.0.0.1"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "10.0.0.1", c.Agent.ServerAddress)
			},
		},
		{
			msg: "server_address specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Agent.ServerAddress = "10.0.0.1"
			},
			cliInput: func(c *agentConfig) {
				c.ServerAddress = "10.0.0.2"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "10.0.0.2", c.Agent.ServerAddress)
			},
		},
		{
			msg: "server_port should be configurable by file",
			fileInput: func(c *config) {
				c.Agent.ServerPort = 1337
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, 1337, c.Agent.ServerPort)
			},
		},
		{
			msg:       "server_port should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *agentConfig) {
				c.ServerPort = 1337
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, 1337, c.Agent.ServerPort)
			},
		},
		{
			msg: "server_port specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Agent.ServerPort = 1336
			},
			cliInput: func(c *agentConfig) {
				c.ServerPort = 1337
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, 1337, c.Agent.ServerPort)
			},
		},
		{
			msg:       "socket_path should default to ./spire_api if not set",
			fileInput: func(c *config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "./spire_api", c.Agent.SocketPath)
			},
		},
		{
			msg: "socket_path should be configurable by file",
			fileInput: func(c *config) {
				c.Agent.SocketPath = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.SocketPath)
			},
		},
		{
			msg:       "socket_path should be configuable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *agentConfig) {
				c.SocketPath = "foo"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.SocketPath)
			},
		},
		{
			msg: "socket_path specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Agent.SocketPath = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.SocketPath = "bar"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "bar", c.Agent.SocketPath)
			},
		},
		{
			msg: "trust_bundle_path should be configurable by file",
			fileInput: func(c *config) {
				c.Agent.TrustBundlePath = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.TrustBundlePath)
			},
		},
		{
			msg:       "trust_bundle_path should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *agentConfig) {
				c.TrustBundlePath = "foo"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.TrustBundlePath)
			},
		},
		{
			msg: "trust_bundle_path specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Agent.TrustBundlePath = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.TrustBundlePath = "bar"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "bar", c.Agent.TrustBundlePath)
			},
		},
		{
			msg:       "trust_domain should not have a default value",
			fileInput: func(c *config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "", c.Agent.TrustDomain)
			},
		},
		{
			msg: "trust_domain should be configurable by file",
			fileInput: func(c *config) {
				c.Agent.TrustDomain = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.TrustDomain)
			},
		},
		{
			// TODO: should it really?
			msg:       "trust_domain should be configurable by CLI flag",
			fileInput: func(c *config) {},
			cliInput: func(c *agentConfig) {
				c.TrustDomain = "foo"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "foo", c.Agent.TrustDomain)
			},
		},
		{
			msg: "trust_domain specified by CLI flag should take precedence over file",
			fileInput: func(c *config) {
				c.Agent.TrustDomain = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.TrustDomain = "bar"
			},
			test: func(t *testing.T, c *config) {
				require.Equal(t, "bar", c.Agent.TrustDomain)
			},
		},
	}

	for _, testCase := range cases {
		fileInput := &config{Agent: &agentConfig{}}
		cliInput := &agentConfig{}

		testCase.fileInput(fileInput)
		testCase.cliInput(cliInput)

		t.Run(testCase.msg, func(t *testing.T) {
			i, err := mergeInput(fileInput, cliInput)
			require.NoError(t, err)

			testCase.test(t, i)
		})
	}
}

func TestNewAgentConfig(t *testing.T) {
	cases := []struct {
		msg         string
		expectError bool
		input       func(*config)
		test        func(*testing.T, *agent.Config)
	}{
		{
			msg: "server_address and server_port should be correctly parsed",
			input: func(c *config) {
				c.Agent.ServerAddress = "192.168.1.1"
				c.Agent.ServerPort = 1337
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "192.168.1.1:1337", c.ServerAddress)
			},
		},
		{
			msg: "trust_domain should be correctly parsed",
			input: func(c *config) {
				c.Agent.TrustDomain = "foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "spiffe://foo", c.TrustDomain.String())
			},
		},
		{
			msg:         "invalid trust_domain should return an error",
			expectError: true,
			input: func(c *config) {
				c.Agent.TrustDomain = "i'm invalid"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "socket_path should be correctly configured",
			input: func(c *config) {
				c.Agent.SocketPath = "foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "foo", c.BindAddress.Name)
				require.Equal(t, "unix", c.BindAddress.Net)
			},
		},
		{
			msg: "join_token should be correctly configured",
			input: func(c *config) {
				c.Agent.JoinToken = "foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "foo", c.JoinToken)
			},
		},
		{
			msg: "data_dir should be correctly configured",
			input: func(c *config) {
				c.Agent.DataDir = "foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "foo", c.DataDir)
			},
		},
		{
			msg: "enable_sds should be correctly configured",
			input: func(c *config) {
				c.Agent.EnableSDS = true
			},
			test: func(t *testing.T, c *agent.Config) {
				require.True(t, c.EnableSDS)
			},
		},
		{
			msg: "logger gets set correctly",
			input: func(c *config) {
				c.Agent.LogLevel = "WARN"
				c.Agent.LogFormat = "TEXT"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.NotNil(t, c.Log)

				l := c.Log.(*log.Logger)
				require.Equal(t, logrus.WarnLevel, l.Level)
				require.Equal(t, &logrus.TextFormatter{}, l.Formatter)
			},
		},
		{
			msg: "log_level and log_format are case insensitive",
			input: func(c *config) {
				c.Agent.LogLevel = "wArN"
				c.Agent.LogFormat = "TeXt"
			},
			test: func(t *testing.T, c *agent.Config) {
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
				c.Agent.LogLevel = "not-a-valid-level"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:         "invalid log_format returns an error",
			expectError: true,
			input: func(c *config) {
				c.Agent.LogFormat = "not-a-valid-format"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
	}

	for _, testCase := range cases {
		input := defaultValidConfig()

		testCase.input(input)

		t.Run(testCase.msg, func(t *testing.T) {
			ac, err := newAgentConfig(input)
			if testCase.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			testCase.test(t, ac)
		})
	}
}

// defaultValidConfig returns the bare minimum config required to
// pass validation etc
func defaultValidConfig() *config {
	c := defaultConfig()

	c.Agent.DataDir = "."
	c.Agent.ServerAddress = "192.168.1.1"
	c.Agent.ServerPort = 1337
	c.Agent.TrustBundlePath = path.Join(util.ProjectRoot(), "conf/agent/dummy_root_ca.crt")
	c.Agent.TrustDomain = "example.org"

	c.Plugins = &catalog.HCLPluginConfigMap{}

	return c
}
