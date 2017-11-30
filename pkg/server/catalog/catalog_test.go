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

func (c *ServerCatalogTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(c.t)
	_, logHook := test.NewNullLogger()

	cat := &catalog{}

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

	plugins := []*common_catalog.ManagedPlugin{
		{
			Plugin: &mock_ca.MockControlPlaneCa{},
			Config: common_catalog.PluginConfig{
				PluginType: CAType,
			},
		},
	}
	comCatalog.EXPECT().Plugins().Return(plugins)

	err := c.catalog.categorize()
	c.Assert().Error(err)
	c.Assert().Contains(err.Error(), "At least one plugin of type")
}

func (c *ServerCatalogTestSuite) TestCategorize() {
	comCatalog := mock_catalog.NewMockCatalog(c.ctrl)
	c.catalog.com = comCatalog

	plugins := []*common_catalog.ManagedPlugin{
		{
			Plugin: &mock_ca.MockControlPlaneCa{},
			Config: common_catalog.PluginConfig{
				PluginType: CAType,
			},
		},
		{
			Plugin: &mock_datastore.MockDataStore{},
			Config: common_catalog.PluginConfig{
				PluginType: DataStoreType,
			},
		},
		{
			Plugin: &mock_nodeattestor.MockNodeAttestor{},
			Config: common_catalog.PluginConfig{
				PluginType: NodeAttestorType,
			},
		},
		{
			Plugin: &mock_noderesolver.MockNodeResolver{},
			Config: common_catalog.PluginConfig{
				PluginType: NodeResolverType,
			},
		},
		{
			Plugin: &mock_upstreamca.MockUpstreamCa{},
			Config: common_catalog.PluginConfig{
				PluginType: UpstreamCAType,
			},
		},
	}
	comCatalog.EXPECT().Plugins().Return(plugins)

	err := c.catalog.categorize()
	c.Assert().Nil(err)
}

func TestCatalog(t *testing.T) {
	suite.Run(t, new(ServerCatalogTestSuite))
}
