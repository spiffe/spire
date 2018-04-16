package catalog

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/mock/common/catalog"
	"github.com/spiffe/spire/test/mock/proto/server/ca"
	"github.com/spiffe/spire/test/mock/proto/server/datastore"
	"github.com/spiffe/spire/test/mock/proto/server/nodeattestor"
	"github.com/spiffe/spire/test/mock/proto/server/noderesolver"
	"github.com/spiffe/spire/test/mock/proto/server/upstreamca"
	"github.com/stretchr/testify/suite"
)

type ServerCatalogTestSuite struct {
	suite.Suite

	catalog *catalog

	// Logrus test hook for asserting
	// log messages, if desired
	logHook *test.Hook

	t    *testing.T
	ctrl *gomock.Controller
}

var plugins = []*common_catalog.ManagedPlugin{
	{
		Plugin: &mock_ca.MockServerCa{},
		Config: common_catalog.PluginConfig{
			Enabled:    true,
			PluginType: CAType,
		},
	},
	{
		Plugin: &mock_datastore.MockDataStore{},
		Config: common_catalog.PluginConfig{
			Enabled:    true,
			PluginType: DataStoreType,
		},
	},
	{
		// Have another DataStore plugin, but disabled
		Plugin: &mock_datastore.MockDataStore{},
		Config: common_catalog.PluginConfig{
			Enabled:    false,
			PluginType: DataStoreType,
		},
	},
	{
		Plugin: &mock_nodeattestor.MockNodeAttestor{},
		Config: common_catalog.PluginConfig{
			Enabled:    true,
			PluginType: NodeAttestorType,
		},
	},
	{
		Plugin: &mock_noderesolver.MockNodeResolver{},
		Config: common_catalog.PluginConfig{
			Enabled:    true,
			PluginType: NodeResolverType,
		},
	},
	{
		Plugin: &mock_upstreamca.MockUpstreamCa{},
		Config: common_catalog.PluginConfig{
			Enabled:    true,
			PluginType: UpstreamCAType,
		},
	},
}

func (c *ServerCatalogTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(c.t)
	log, logHook := test.NewNullLogger()

	cat := &catalog{
		log: log,
	}

	c.catalog = cat
	c.ctrl = mockCtrl
	c.logHook = logHook
}

func (c *ServerCatalogTestSuite) TeardownTest() {
	c.ctrl.Finish()
}

func (c *ServerCatalogTestSuite) TestCategorizeNotEnoughTypes() {
	comCatalog := mock_catalog.NewMockCatalog(c.ctrl)
	c.catalog.com = comCatalog
	var expectedErr = "At least one plugin of type"

	// Have all plugins, but one disabled
	plugins[0].Config.Enabled = false
	comCatalog.EXPECT().Plugins().Return(plugins)
	err := c.catalog.categorize()
	c.Assert().Error(err)
	c.Assert().Contains(err.Error(), expectedErr)

	// Have only one plugin
	var onePlugin = []*common_catalog.ManagedPlugin{
		{
			Plugin: &mock_ca.MockServerCa{},
			Config: common_catalog.PluginConfig{
				Enabled:    true,
				PluginType: CAType,
			},
		},
	}
	comCatalog.EXPECT().Plugins().Return(onePlugin)
	err = c.catalog.categorize()
	c.Assert().Error(err)
	c.Assert().Contains(err.Error(), expectedErr)
}

func (c *ServerCatalogTestSuite) TestCategorize() {
	comCatalog := mock_catalog.NewMockCatalog(c.ctrl)
	c.catalog.com = comCatalog

	comCatalog.EXPECT().Plugins().Return(plugins)

	err := c.catalog.categorize()
	c.Assert().Nil(err)
}

func TestCatalog(t *testing.T) {
	suite.Run(t, new(ServerCatalogTestSuite))
}
