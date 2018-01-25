package run

import (
	"bytes"
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
	expectedData := "join_token = \"PLUGIN-AGENT-NOT-A-SECRET\"\n\ntrust_domain = \"example.org\""
	var data bytes.Buffer
	err = printer.DefaultConfig.Fprint(&data, c.PluginsConfigs["plugin_type_agent"]["plugin_name_agent"].PluginData)
	assert.NoError(t, err)

	assert.Equal(t, len(c.PluginsConfigs), 1)
	assert.Equal(t, c.PluginsConfigs["plugin_type_agent"]["plugin_name_agent"].Enabled, true)
	assert.Equal(t, c.PluginsConfigs["plugin_type_agent"]["plugin_name_agent"].PluginChecksum, "pluginAgentChecksum")
	assert.Equal(t, c.PluginsConfigs["plugin_type_agent"]["plugin_name_agent"].PluginCmd, "./pluginAgentCmd")
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
	ac := &agentConfig{
		DataDir:       ".",
		LogLevel:      "INFO",
		ServerAddress: "127.0.0.1",
		ServerPort:    8081,
		SocketPath:    "/tmp/agent.sock",
		TrustDomain:   "example.org",
		Umask:         "",
	}

	c := &runConfig{
		AgentConfig: *ac,
	}

	orig := newDefaultConfig()
	err := mergeConfig(orig, c)
	require.NoError(t, err)
	assert.Equal(t, orig.ServerAddress.IP.String(), "127.0.0.1")
	assert.Equal(t, orig.ServerAddress.Port, 8081)
	assert.Equal(t, orig.TrustDomain.Scheme, "spiffe")
	assert.Equal(t, orig.TrustDomain.Host, "example.org")
	assert.Equal(t, orig.DataDir, ".")
	assert.Equal(t, orig.Umask, 0077)
}
