package helpers

import (
	"io/ioutil"
	"testing"

	//"github.com/stretchr/testify/assert"
	"os"

	"github.com/hashicorp/go-plugin"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type MockGRPCClient struct {
	mock.Mock
}

// ClientProtocol impl.
func (c MockGRPCClient) Close() error {
	return nil
}

// ClientProtocol impl.
func (c MockGRPCClient) Dispense(name string) (interface{}, error) {
	return nil, nil
}

// ClientProtocol impl.
func (c MockGRPCClient) Ping() error {
	return nil

}

type MockClient struct {
	mock.Mock
}

func (mc *MockClient) Client() (pcl plugin.ClientProtocol, err error) {
	args := mc.Called()

	return args.Get(0).(MockGRPCClient), args.Error(1)
}

type PluginHelperTestSuite struct {
	suite.Suite
	configfileContent []byte
	dir               string
	file              *os.File
	plugincat         *PluginCatalogImpl
}

func (suite *PluginHelperTestSuite) SetupTest() {
	suite.configfileContent = []byte("pluginName = \"testPlugin\"\n" +
		"pluginCmd = \"testCommand\"\n" +
		"pluginChecksum = \"1234\"\n" +
		"enabled = true\n" +
		"pluginType = \"testPluginType\"\n" +
		"pluginData {\n" +
		"}\n")

	dir, err := ioutil.TempDir("", "test_NA_conf")
	if err != nil {
		suite.NoError(err)
	}
	suite.dir = dir

	file, err := ioutil.TempFile(dir, "test_na_plugin")
	if err != nil {
		suite.NoError(err)
	}
	suite.file = file

	err = ioutil.WriteFile(file.Name(), suite.configfileContent, 775)
	if err != nil {
		suite.NoError(err)
	}

	suite.plugincat = NewPluginCatalog(
		&PluginCatalogConfig{PluginConfDirectory: suite.dir})

}

func (suite *PluginHelperTestSuite) TestPluginCatalog_Run() {

	err := suite.plugincat.Run()
	if err != nil {
		suite.Error(err)
	}
}

func TestPluginHelperTestSuite(t *testing.T) {
	client := new(MockClient)
	client.On("Client").Return(MockGRPCClient{}, nil)

	suite.Run(t, new(PluginHelperTestSuite))
}
