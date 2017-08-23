package helpers

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

type ConfigTestSuite struct {
	suite.Suite
	configfileContent map[ConfigType][]byte
	testPluginConfig  *PluginConfig
	testNAConfig      *NodeAgentConfig
	testCPConfig      *ControlPlaneConfig
}

type ConfigType int

const (
	NodeAgentConfigType ConfigType = iota
	ControlPlaneConfigType
	PluginConfigType
)

func (suite *ConfigTestSuite) SetupTest() {

	suite.configfileContent = make(map[ConfigType][]byte)

	suite.testPluginConfig = &PluginConfig{
		Version:        "testVersion",
		PluginName:     "testPlugin",
		PluginCmd:      "testCommand",
		PluginChecksum: "1234",
		Enabled:        true,
		PluginType:     "testPluginType",
		PluginData:     "testkey = \"testVadata\"",
	}

	suite.configfileContent[PluginConfigType] = []byte(
		"version =\"" + suite.testPluginConfig.Version + "\"\n" +
			"pluginName =\"" + suite.testPluginConfig.PluginName + "\"\n" +
			"pluginCmd = \"" + suite.testPluginConfig.PluginCmd + "\"\n" +
			"pluginChecksum = \"" + suite.testPluginConfig.PluginChecksum + "\"\n" +
			"enabled = true" +"\n" +
			"pluginType = \"" + suite.testPluginConfig.PluginType + "\"\n" +
			"pluginData {" + suite.testPluginConfig.PluginData + "\n" +
			"}\n")

	suite.testNAConfig = &NodeAgentConfig{
		Version:            "testVersion",
		WorkloadAPIAddress: "testworkloadAPIAddress",
	}
	suite.configfileContent[NodeAgentConfigType] = []byte(
		"version =\"" + suite.testNAConfig.Version + "\"\n" +
			"workloadAPIAddress = \"" + suite.testNAConfig.WorkloadAPIAddress + "\"\n")

	suite.testCPConfig = &ControlPlaneConfig{
		Version:                 "testVersion",
		NodeAPIGRPCPort:         "testnodeAPIAddress",
		RegistrationAPIGRPCPort: "testRegistrationAPIAddress",
	}
	suite.configfileContent[ControlPlaneConfigType] = []byte(
		"version =\"" + suite.testCPConfig.Version + "\"\n" +
			"nodeAPIAddress = \"" + suite.testCPConfig.NodeAPIGRPCPort + "\"\n" +
			"registrationAPIAddress = \"" + suite.testCPConfig.RegistrationAPIGRPCPort + "\"\n")

}

func (suite *ConfigTestSuite) TestParsePluginConfig() {
		content:=suite.configfileContent[PluginConfigType]
		tempDir := os.TempDir()
		file, err := ioutil.TempFile(tempDir, "testconfig")
		if err != nil {
			suite.NoError(err)
		}
		err = ioutil.WriteFile(file.Name(), content, 775)
		if err != nil {
			suite.NoError(err)
		}
		pluginConfig := &PluginConfig{}
		err = pluginConfig.ParseConfig(file.Name())
		suite.NoError(err)
		suite.Equal(pluginConfig.Version, suite.testPluginConfig.Version)
		suite.Equal(pluginConfig.PluginName, suite.testPluginConfig.PluginName)
		suite.Equal(pluginConfig.PluginCmd, suite.testPluginConfig.PluginCmd)
		suite.Equal(pluginConfig.PluginChecksum, suite.testPluginConfig.PluginChecksum)
		suite.Equal(pluginConfig.PluginData, suite.testPluginConfig.PluginData)
		suite.Equal(pluginConfig.PluginType, suite.testPluginConfig.PluginType)
}

func (suite *ConfigTestSuite) TestParseNodeAgentConfig() {
	content := suite.configfileContent[NodeAgentConfigType]
	tempDir := os.TempDir()
	file, err := ioutil.TempFile(tempDir, "testconfig")
	if err != nil {
		suite.NoError(err)
	}
	err = ioutil.WriteFile(file.Name(), content, 775)
	if err != nil {
		suite.NoError(err)
	}
	nodeAgentConfig := NodeAgentConfig{}
	err = nodeAgentConfig.ParseConfig(file.Name())
	suite.NoError(err)
	suite.Equal(nodeAgentConfig.Version, suite.testNAConfig.Version)
	suite.Equal(nodeAgentConfig.WorkloadAPIAddress, suite.testNAConfig.WorkloadAPIAddress)
}

func (suite *ConfigTestSuite) TestParseControlPlaneConfig() {
	content := suite.configfileContent[ControlPlaneConfigType]
	tempDir := os.TempDir()
	file, err := ioutil.TempFile(tempDir, "testconfig")
	if err != nil {
		suite.NoError(err)
	}
	err = ioutil.WriteFile(file.Name(), content, 775)
	if err != nil {
		suite.NoError(err)
	}
	controlPlaneConfig := ControlPlaneConfig{}
	err = controlPlaneConfig.ParseConfig(file.Name())
	suite.NoError(err)
	suite.Equal(controlPlaneConfig.Version, suite.testCPConfig.Version)
	suite.Equal(controlPlaneConfig.NodeAPIGRPCPort, suite.testCPConfig.NodeAPIGRPCPort)

}

func TestConfig_TestParseConfigTestSuite(t *testing.T) {
	suite.Run(t, new(ConfigTestSuite))
}

func TestConfig_ParseValidConfig(t *testing.T) {
	var configs = map[string]struct {
		Version        string
		PluginName     string
		PluginCmd      string
		PluginChecksum string
		PluginType     string
		Enabled        bool
		PluginData     string
	}{
		"plugin_valid_conf_1.hcl": {
			"testVersion1",
			"pluginName1",
			"pluginCmd1",
			"pluginChecksum1",
			"pluginType1",
			true,
			"Data1 = \"Data1\""},
		"plugin_valid_conf_2.hcl": {
			"testVersion2",
			"pluginName2",
			"pluginCmd2",
			"pluginChecksum2",
			"pluginType2",
			false,
			"Data2 = \"Data2\"\n\nData1 = 123\n\nData3 = true\n\ndata4 = 12342"}}

	const pluginConfDirectory string = "../helpers/test_data_valid"
	configFiles, err := ioutil.ReadDir(pluginConfDirectory)
	assert.NoError(t, err)

	for _, configFile := range configFiles {
		pluginConfig := &PluginConfig{}
		err := pluginConfig.ParseConfig(filepath.Join(pluginConfDirectory, configFile.Name()))
		assert.NoError(t, err)
		assert.Equal(t, configs[configFile.Name()].Version, pluginConfig.Version)
		assert.Equal(t, configs[configFile.Name()].Enabled, pluginConfig.Enabled)
		assert.Equal(t, configs[configFile.Name()].PluginChecksum, pluginConfig.PluginChecksum)
		assert.Equal(t, configs[configFile.Name()].PluginCmd, pluginConfig.PluginCmd)
		assert.Equal(t, configs[configFile.Name()].PluginName, pluginConfig.PluginName)
		assert.Equal(t, configs[configFile.Name()].PluginType, pluginConfig.PluginType)
		assert.Equal(t, configs[configFile.Name()].PluginData, pluginConfig.PluginData)
	}
}

func TestConfig_ParseInvalidConfig(t *testing.T) {
	const pluginConfDirectory string = "../helpers/test_data_invalid"

	configFiles, err := ioutil.ReadDir(pluginConfDirectory)
	assert.NoError(t, err)

	for _, configFile := range configFiles {
		pluginConfig := &PluginConfig{}
		err := pluginConfig.ParseConfig(filepath.Join(pluginConfDirectory, configFile.Name()))
		assert.Error(t, err)
	}
}
