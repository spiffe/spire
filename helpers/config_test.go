package pluginhelper

import (
	"io/ioutil"
	"path/filepath"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestConfig_ParseValidConfig(t *testing.T) {
	var configs = map[string]struct {PluginName string
		PluginCmd string
		PluginChecksum string
		PluginType string
		Enabled bool
		PluginData string
		} {
		"plugin_valid_conf_1.hcl": {
			"pluginName1",
			"pluginCmd1",
			"pluginChecksum1",
			"pluginType1",
			true,
			"Data1 = \"Data1\""},
		"plugin_valid_conf_2.hcl": {
			"pluginName2",
			"pluginCmd2",
			"pluginChecksum2",
			"pluginType2",
			false,
			"Data2 = \"Data2\""},}

	const pluginConfDirectory string = "../helpers/test_data_valid"
	configFiles, err := ioutil.ReadDir(pluginConfDirectory)
	assert.NoError(t, err)

	for _, configFile := range configFiles {
		config, err := ParseConfig(filepath.Join(pluginConfDirectory, configFile.Name()))
		assert.NoError(t, err)
		assert.NotNil(t, config)
		assert.Equal(t, configs[configFile.Name()].Enabled, config.Enabled)
		assert.Equal(t, configs[configFile.Name()].PluginChecksum, config.PluginChecksum)
		assert.Equal(t, configs[configFile.Name()].PluginCmd, config.PluginCmd)
		assert.Equal(t, configs[configFile.Name()].PluginName, config.PluginName)
		assert.Equal(t, configs[configFile.Name()].PluginType, config.PluginType)
		assert.Equal(t, configs[configFile.Name()].PluginData, config.PluginData)
	}
}

func TestConfig_ParseInvalidConfig(t *testing.T) {
	const pluginConfDirectory string = "../helpers/test_data_invalid"

	configFiles, err := ioutil.ReadDir(pluginConfDirectory)
	assert.NoError(t, err)

	for _, configFile := range configFiles {
		config, err := ParseConfig(filepath.Join(pluginConfDirectory, configFile.Name()))
		assert.Error(t, err)
		assert.Nil(t, config)
	}
}
