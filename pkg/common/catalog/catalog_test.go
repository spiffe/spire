package catalog

import (
	"net/rpc"
	"os/exec"
	"testing"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/golang/mock/gomock"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl"
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
	pluginData, err := hcl.ParseString(`
		join_token = "NOT-A-SECRET"`)

	c.Assert().NoError(err)
	cat := &catalog{
		pluginConfigs: PluginConfigMap{"NodeAttestor": {"join_token": HclPluginConfig{
			PluginCmd:  "./attestor",
			Enabled:    to.BoolPtr(true),
			PluginData: pluginData,
		}}},
		supportedPlugins: supportedPlugins,
		globalConfig:     &GlobalConfig{TrustDomain: "example.org"},
		l:                log,
	}

	c.catalog = cat
	c.ctrl = mockCtrl
	c.logHook = logHook
}

func (c *CatalogTestSuite) TearDownTest() {
	c.ctrl.Finish()
}

func (c *CatalogTestSuite) TestLoadConfigs() {
	err := c.catalog.loadConfigs()
	if !c.Assert().Nil(err) || !c.Assert().Equal(1, len(c.catalog.plugins)) {
		c.Assert().FailNow("error parsing plugin config")
	}

	p := c.catalog.plugins[0]
	c.Assert().Equal("join_token", p.Config.PluginName)
	c.Assert().Equal(true, p.Config.Enabled)

	expectedData := "join_token = \"NOT-A-SECRET\""
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

	_ = c.catalog.loadConfigs()
	pluginConfig, err := c.catalog.newPluginConfig(c.catalog.plugins[0])
	if c.Assert().Nil(err) {
		c.Assert().Equal(expectedConfig, pluginConfig)
	}
}

func TestCatalog(t *testing.T) {
	suite.Run(t, new(CatalogTestSuite))
}
