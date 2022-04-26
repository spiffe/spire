//go:build !windows
// +build !windows

package run

import (
	"bytes"
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
		"-socketPath=/tmp/spire-agent/public/api.sock",
		"-trustBundle=conf/agent/dummy_root_ca.crt",
		"-trustBundleUrl=https://test.url",
		"-trustDomain=example.org",
		"-allowUnauthenticatedVerifiers",
	}, os.Stderr)
	require.NoError(t, err)
	assert.Equal(t, c.DataDir, ".")
	assert.Equal(t, c.LogLevel, "INFO")
	assert.Equal(t, c.ServerAddress, "127.0.0.1")
	assert.Equal(t, c.ServerPort, 8081)
	assert.Equal(t, c.SocketPath, "/tmp/spire-agent/public/api.sock")
	assert.Equal(t, c.TrustBundlePath, "conf/agent/dummy_root_ca.crt")
	assert.Equal(t, c.TrustBundleURL, "https://test.url")
	assert.Equal(t, c.TrustDomain, "example.org")
	assert.Equal(t, c.AllowUnauthenticatedVerifiers, true)
}

func TestParseConfigGood(t *testing.T) {
	c, err := ParseFile("../../../../test/fixture/config/agent_good_posix.conf", false)
	require.NoError(t, err)
	assert.Equal(t, ".", c.Agent.DataDir)
	assert.Equal(t, "INFO", c.Agent.LogLevel)
	assert.Equal(t, "127.0.0.1", c.Agent.ServerAddress)
	assert.Equal(t, 8081, c.Agent.ServerPort)
	assert.Equal(t, "/tmp/spire-agent/public/api.sock", c.Agent.SocketPath)
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
	assert.Equal(t, true, pluginConfig.IsEnabled())
	assert.Equal(t, "pluginAgentChecksum", pluginConfig.PluginChecksum)
	assert.Equal(t, "./pluginAgentCmd", pluginConfig.PluginCmd)
	assert.Equal(t, data.String(), expectedData)

	// Disabled plugin
	pluginConfig = pluginConfigs["plugin_type_agent"]["plugin_disabled"]
	assert.NotNil(t, pluginConfig.Enabled)
	assert.Equal(t, false, pluginConfig.IsEnabled())
	assert.Equal(t, "pluginAgentChecksum", pluginConfig.PluginChecksum)
	assert.Equal(t, "./pluginAgentCmd", pluginConfig.PluginCmd)
	assert.Equal(t, data.String(), expectedData)

	// Enabled plugin
	pluginConfig = pluginConfigs["plugin_type_agent"]["plugin_enabled"]
	assert.NotNil(t, pluginConfig.Enabled)
	assert.Equal(t, true, pluginConfig.IsEnabled())
	assert.Equal(t, "pluginAgentChecksum", pluginConfig.PluginChecksum)
	assert.Equal(t, "./pluginAgentCmd", pluginConfig.PluginCmd)
	assert.Equal(t, data.String(), expectedData)
}

func mergeInputCasesOS() []mergeInputCase {
	return []mergeInputCase{
		{
			msg:       "socket_path should default to /tmp/spire-agent/public/api.sock if not set",
			fileInput: func(c *Config) {},
			cliInput:  func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "/tmp/spire-agent/public/api.sock", c.Agent.SocketPath)
			},
		},
		{
			msg: "socket_path should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.SocketPath = "foo"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.SocketPath)
			},
		},
		{
			msg:       "socket_path should be configuable by CLI flag",
			fileInput: func(c *Config) {},
			cliInput: func(c *agentConfig) {
				c.SocketPath = "foo"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "foo", c.Agent.SocketPath)
			},
		},
		{
			msg: "socket_path specified by CLI flag should take precedence over file",
			fileInput: func(c *Config) {
				c.Agent.SocketPath = "foo"
			},
			cliInput: func(c *agentConfig) {
				c.SocketPath = "bar"
			},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "bar", c.Agent.SocketPath)
			},
		},
		{
			msg: "admin_socket_path should be configurable by file",
			fileInput: func(c *Config) {
				c.Agent.AdminSocketPath = "/tmp/admin.sock"
			},
			cliInput: func(c *agentConfig) {},
			test: func(t *testing.T, c *Config) {
				require.Equal(t, "/tmp/admin.sock", c.Agent.AdminSocketPath)
			},
		},
	}
}

func newAgentConfigCasesOS() []newAgentConfigCase {
	return []newAgentConfigCase{
		{
			msg: "socket_path should be correctly configured",
			input: func(c *Config) {
				c.Agent.SocketPath = "/foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "/foo", c.BindAddress.String())
				require.Equal(t, "unix", c.BindAddress.Network())
			},
		},
		{
			msg: "admin_socket_path should be correctly configured",
			input: func(c *Config) {
				c.Agent.AdminSocketPath = "/foo"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "/foo", c.AdminBindAddress.String())
				require.Equal(t, "unix", c.AdminBindAddress.Network())
			},
		},
		{
			msg: "admin_socket_path configured with similar folther that socket_path",
			input: func(c *Config) {
				c.Agent.SocketPath = "/tmp/workload/workload.sock"
				c.Agent.AdminSocketPath = "/tmp/workload-admin/admin.sock"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "/tmp/workload-admin/admin.sock", c.AdminBindAddress.String())
				require.Equal(t, "unix", c.AdminBindAddress.Network())
			},
		},
		{
			msg: "admin_socket_path should be correctly configured in different folder",
			input: func(c *Config) {
				c.Agent.SocketPath = "/tmp/workload/workload.sock"
				c.Agent.AdminSocketPath = "/tmp/admin.sock"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Equal(t, "/tmp/workload/workload.sock", c.BindAddress.String())
				require.Equal(t, "unix", c.BindAddress.Network())
				require.Equal(t, "/tmp/admin.sock", c.AdminBindAddress.String())
				require.Equal(t, "unix", c.AdminBindAddress.Network())
			},
		},
		{
			msg:         "admin_socket_path same folder as socket_path",
			expectError: true,
			input: func(c *Config) {
				c.Agent.SocketPath = "/tmp/workload.sock"
				c.Agent.AdminSocketPath = "/tmp/admin.sock"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:         "admin_socket_path configured with subfolder socket_path",
			expectError: true,
			input: func(c *Config) {
				c.Agent.SocketPath = "/tmp/workload.sock"
				c.Agent.AdminSocketPath = "/tmp/admin/admin.sock"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg:         "admin_socket_path relative folder",
			expectError: true,
			input: func(c *Config) {
				c.Agent.SocketPath = "./sock/workload.sock"
				c.Agent.AdminSocketPath = "./sock/admin.sock"
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c)
			},
		},
		{
			msg: "admin_socket_path not provided",
			input: func(c *Config) {
				c.Agent.AdminSocketPath = ""
			},
			test: func(t *testing.T, c *agent.Config) {
				require.Nil(t, c.AdminBindAddress)
			},
		},
	}
}
