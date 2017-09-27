package catalog

import (
	"net/rpc"
	"os/exec"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/go-plugin"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/log"
	"github.com/stretchr/testify/suite"
)

// testPlugin is a dummy struct conforming
// to the plugin.Plugin interface
type testPlugin struct{}

func (testPlugin) Server(_ *plugin.MuxBroker) (interface{}, error)                { return nil, nil }
func (testPlugin) Client(_ *plugin.MuxBroker, _ *rpc.Client) (interface{}, error) { return nil, nil }

type CatalogTestSuite struct {
	suite.Suite

	catalog *catalog

	// Logrus test hook for asserting
	// log messages, if desired
	logHook *test.Hook

	t    *testing.T
	ctrl *gomock.Controller
}

func (c *CatalogTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(c.t)
	log, logHook := test.NewNullLogger()

	supportedPlugins := map[string]plugin.Plugin{
		"NodeAttestor": testPlugin{},
	}
	cat := &catalog{
		configDir:        "NONEXISTENT",
		supportedPlugins: supportedPlugins,
		l:                log,
	}

	c.catalog = cat
	c.ctrl = mockCtrl
	c.logHook = logHook
}

func (c *CatalogTestSuite) TeardownTest() {
	c.ctrl.Finish()
}

func (c *CatalogTestSuite) TestLoadConfig() {
	err := c.catalog.loadConfig("../../../test/fixture/config/plugin_good.conf")
	if !c.Assert().Nil(err) || !c.Assert().Equal(1, len(c.catalog.plugins)) {
		c.Assert().FailNow("error parsing plugin config")
	}

	p := c.catalog.plugins[0]
	c.Assert().Equal("join_token", p.Config.PluginName)
	c.Assert().Equal(true, p.Config.Enabled)

	expectedData := "join_token = \"NOT-A-SECRET\"\n\ntrust_domain = \"example.org\""
	c.Assert().Equal(expectedData, p.Config.PluginData)
}

func (c *CatalogTestSuite) TestNewPluginConfig() {
	expectedConfig := &plugin.ClientConfig{
		HandshakeConfig: plugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   "NodeAttestor",
			MagicCookieValue: "NodeAttestor",
		},
		Plugins:          map[string]plugin.Plugin{"join_token": testPlugin{}},
		Cmd:              exec.Command("./attestor"),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		Managed:          true,
		SecureConfig:     nil,
		Logger: &log.HCLogAdapter{
			Log:  c.catalog.l.WithField("plugin_type", "NodeAttestor").WithField("plugin_name", "join_token"),
			Name: "plugin",
		},
	}

	_ = c.catalog.loadConfig("../../../test/fixture/config/plugin_good.conf")
	pluginConfig, err := c.catalog.newPluginConfig(c.catalog.plugins[0])
	if c.Assert().Nil(err) {
		c.Assert().Equal(expectedConfig, pluginConfig)
	}
}

func TestCatalog(t *testing.T) {
	suite.Run(t, new(CatalogTestSuite))
}
