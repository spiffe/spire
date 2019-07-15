package run

import (
	"bytes"
	"net"
	"testing"

	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/log"
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

func TestMergeConfigGood(t *testing.T) {
	ac := &agentConfig{
		DataDir:         ".",
		LogLevel:        "WARN",
		ServerAddress:   "127.0.0.1",
		ServerPort:      8081,
		SocketPath:      "/tmp/agent.sock",
		TrustDomain:     "example.org",
		TrustBundlePath: "../../../../conf/agent/dummy_root_ca.crt",
	}

	dc := defaultConfig()
	dc.Plugins = &catalog.HCLPluginConfigMap{}
	dc.Agent.LogFormat = "json"

	c, err := processInput(dc, ac)
	require.NoError(t, err)
	assert.Equal(t, c.ServerAddress, net.JoinHostPort("127.0.0.1", "8081"))
	assert.Equal(t, c.TrustDomain.Scheme, "spiffe")
	assert.Equal(t, c.TrustDomain.Host, "example.org")
	assert.Equal(t, c.DataDir, ".")
	assert.Equal(t, c.Log.(*log.Logger).Level, logrus.WarnLevel)
}
