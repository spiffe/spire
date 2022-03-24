//go:build windows
// +build windows

package run

import (
	"bytes"
	"net"
	"os"
	"testing"

	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFlagsGood(t *testing.T) {
	c, err := parseFlags("run", []string{
		"-dataDir=.",
		"-logLevel=INFO",
		"-serverAddress=127.0.0.1",
		"-serverPort=8081",
		"-tcpSocketPort=8082",
		"-trustBundle=conf/agent/dummy_root_ca.crt",
		"-trustBundleUrl=https://test.url",
		"-trustDomain=example.org",
		"-allowUnauthenticatedVerifiers",
	}, os.Stderr)
	require.NoError(t, err)
	assert.Equal(t, ".", c.DataDir)
	assert.Equal(t, "INFO", c.LogLevel)
	assert.Equal(t, "127.0.0.1", c.ServerAddress)
	assert.Equal(t, 8081, c.ServerPort)
	assert.Equal(t, 8082, c.Experimental.TCPSocketPort)
	assert.Equal(t, "conf/agent/dummy_root_ca.crt", c.TrustBundlePath)
	assert.Equal(t, "https://test.url", c.TrustBundleURL)
	assert.Equal(t, "example.org", c.TrustDomain)
	assert.Equal(t, true, c.AllowUnauthenticatedVerifiers)
}

func TestParseConfigGood(t *testing.T) {
	c, err := ParseFile("../../../../test/fixture/config/agent_good_windows.conf", false)
	require.NoError(t, err)
	assert.Equal(t, ".", c.Agent.DataDir)
	assert.Equal(t, "INFO", c.Agent.LogLevel)
	assert.Equal(t, "127.0.0.1", c.Agent.ServerAddress)
	assert.Equal(t, 8081, c.Agent.ServerPort)
	assert.Equal(t, 8082, c.Agent.Experimental.TCPSocketPort)
	assert.Equal(t, "conf/agent/dummy_root_ca.crt", c.Agent.TrustBundlePath)
	assert.Equal(t, "example.org", c.Agent.TrustDomain)
	assert.Equal(t, true, c.Agent.AllowUnauthenticatedVerifiers)
	assert.Equal(t, []string{"c1", "c2", "c3"}, c.Agent.AllowedForeignJWTClaims)

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
	assert.Equal(t, pluginConfig.PluginCmd, ".\\pluginAgentCmd")
	assert.Equal(t, expectedData, data.String())

	// Enabled plugin
	pluginConfig = pluginConfigs["plugin_type_agent"]["plugin_enabled"]
	assert.NotNil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), true)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginAgentChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, "c:/temp/pluginAgentCmd")
	assert.Equal(t, expectedData, data.String())
}

func mergeInputCasesOS() []mergeInputCase {
	return []mergeInputCase{
		{
			msg:       "tcp_socket_port should default to 8082 if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 8082, c.Agent.Experimental.TCPSocketPort)
			},
		},
		{
			msg: "tcp_socket_port should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.Experimental.TCPSocketPort = 1000
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 1000, c.Agent.Experimental.TCPSocketPort)
			},
		},
		{
			msg:       "tcp_socket_port should be configuable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.Experimental.TCPSocketPort = 1000
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 1000, c.Agent.Experimental.TCPSocketPort)
			},
		},
		{
			msg: "tcp_socket_port specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.Experimental.TCPSocketPort = 1000
			},
			cliInput: func(c *agentConfig) {
				c.Experimental.TCPSocketPort = 2000
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, 2000, c.Agent.Experimental.TCPSocketPort)
			},
		},
	}
}

func newAgentConfigCasesOS() []newAgentConfigCase {
	return []newAgentConfigCase{
		{
			msg: "tcp_socket_port should be correctly configured",
			input: func(c *Config) {
				c.Agent.Experimental.TCPSocketPort = 1000
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, net.IPv4(127, 0, 0, 1), c.BindAddress.(*net.TCPAddr).IP)
				require.Equal(t, 1000, c.BindAddress.(*net.TCPAddr).Port)
				require.Equal(t, "tcp", c.BindAddress.(*net.TCPAddr).Network())
			},
		},
	}
}
