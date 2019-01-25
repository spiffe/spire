package run

import (
	"bytes"
	"net"
	"testing"

	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigGood(t *testing.T) {
	c, err := parseFile("../../../../test/fixture/config/agent_good.conf")
	require.NoError(t, err)
	assert.Equal(t, c.AgentConfig.DataDir, ".")
	assert.Equal(t, c.AgentConfig.LogLevel, "INFO")
	assert.Equal(t, c.AgentConfig.ServerAddress, "127.0.0.1")
	assert.Equal(t, c.AgentConfig.ServerPort, 8081)
	assert.Equal(t, c.AgentConfig.SocketPath, "/tmp/agent.sock")
	assert.Equal(t, c.AgentConfig.TrustBundlePath, "conf/agent/dummy_root_ca.crt")
	assert.Equal(t, c.AgentConfig.TrustDomain, "example.org")
	assert.Equal(t, c.AgentConfig.Umask, "")

	// Check for plugins configurations
	expectedData := "join_token = \"PLUGIN-AGENT-NOT-A-SECRET\""
	var data bytes.Buffer
	err = printer.DefaultConfig.Fprint(&data, c.PluginConfigs["plugin_type_agent"]["plugin_name_agent"].PluginData)
	assert.NoError(t, err)

	assert.Len(t, c.PluginConfigs, 1)
	assert.Len(t, c.PluginConfigs["plugin_type_agent"], 3)

	pluginConfig := c.PluginConfigs["plugin_type_agent"]["plugin_name_agent"]
	assert.Nil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), true)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginAgentChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, "./pluginAgentCmd")
	assert.Equal(t, expectedData, data.String())

	// Disabled plugin
	pluginConfig = c.PluginConfigs["plugin_type_agent"]["plugin_disabled"]
	assert.NotNil(t, pluginConfig.Enabled)
	assert.Equal(t, pluginConfig.IsEnabled(), false)
	assert.Equal(t, pluginConfig.PluginChecksum, "pluginAgentChecksum")
	assert.Equal(t, pluginConfig.PluginCmd, "./pluginAgentCmd")
	assert.Equal(t, expectedData, data.String())

	// Enabled plugin
	pluginConfig = c.PluginConfigs["plugin_type_agent"]["plugin_enabled"]
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
		"-umask=",
	})
	require.NoError(t, err)
	assert.Equal(t, c.AgentConfig.DataDir, ".")
	assert.Equal(t, c.AgentConfig.LogLevel, "INFO")
	assert.Equal(t, c.AgentConfig.ServerAddress, "127.0.0.1")
	assert.Equal(t, c.AgentConfig.ServerPort, 8081)
	assert.Equal(t, c.AgentConfig.SocketPath, "/tmp/agent.sock")
	assert.Equal(t, c.AgentConfig.TrustBundlePath, "conf/agent/dummy_root_ca.crt")
	assert.Equal(t, c.AgentConfig.TrustDomain, "example.org")
	assert.Equal(t, c.AgentConfig.Umask, "")
}

func TestMergeConfigGood(t *testing.T) {
	ac := &agentRunConfig{
		DataDir:       ".",
		LogLevel:      "INFO",
		ServerAddress: "127.0.0.1",
		ServerPort:    8081,
		SocketPath:    "/tmp/agent.sock",
		TrustDomain:   "example.org",
		Umask:         "077",
	}

	c := &runConfig{
		AgentConfig: *ac,
	}

	orig := newDefaultConfig()
	assert.Equal(t, orig.umask, -1)

	err := mergeConfig(orig, c)
	require.NoError(t, err)
	assert.Equal(t, orig.ServerAddress, net.JoinHostPort("127.0.0.1", "8081"))
	assert.Equal(t, orig.TrustDomain.Scheme, "spiffe")
	assert.Equal(t, orig.TrustDomain.Host, "example.org")
	assert.Equal(t, orig.GlobalConfig().TrustDomain, "example.org")
	assert.Equal(t, orig.DataDir, ".")
	assert.Equal(t, orig.umask, 077)
}
