package run

import (
	"bytes"
	"testing"

	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/log"
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

func TestMergeConfigGood(t *testing.T) {
	sc := &serverConfig{
		BindAddress:         "127.0.0.1",
		BindPort:            8081,
		DataDir:             ".",
		RegistrationUDSPath: "/tmp/server.sock",
		TrustDomain:         "example.org",
		LogFormat:           "json",
	}

	dc := defaultConfig()
	dc.Plugins = &catalog.HCLPluginConfigMap{}
	dc.Server.LogLevel = "WARN"

	c, err := processInput(dc, sc)
	require.NoError(t, err)
	assert.Equal(t, c.BindAddress.IP.String(), "127.0.0.1")
	assert.Equal(t, c.BindUDSAddress.Name, "/tmp/server.sock")
	assert.Equal(t, c.BindUDSAddress.Net, "unix")
	assert.Equal(t, c.BindAddress.Port, 8081)
	assert.Equal(t, c.TrustDomain.Scheme, "spiffe")
	assert.Equal(t, c.TrustDomain.Host, "example.org")
	assert.Equal(t, c.Log.(*log.Logger).Level, logrus.WarnLevel)
}
