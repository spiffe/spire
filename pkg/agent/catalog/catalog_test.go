package catalog

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
	"github.com/spiffe/spire/test/mock/common/catalog"
	"github.com/spiffe/spire/test/mock/proto/agent/keymanager"
	"github.com/spiffe/spire/test/mock/proto/agent/nodeattestor"
	"github.com/spiffe/spire/test/mock/proto/agent/workloadattestor"
	"github.com/stretchr/testify/suite"
)

var plugins = []*common_catalog.ManagedPlugin{
	{
		Plugin: keymanager.NewBuiltIn(&mock_keymanager.MockPlugin{}),
		Config: common_catalog.PluginConfig{
			PluginType: KeyManagerType,
			Enabled:    true,
		},
	},
	{
		Plugin: nodeattestor.NewBuiltIn(&mock_nodeattestor.MockPlugin{}),
		Config: common_catalog.PluginConfig{
			PluginType: NodeAttestorType,
			Enabled:    true,
		},
	},
	{
		Plugin: workloadattestor.NewBuiltIn(&mock_workloadattestor.MockPlugin{}),
		Config: common_catalog.PluginConfig{
			PluginType: WorkloadAttestorType,
			Enabled:    true,
		},
	},
	{
		// Have another WorkloadAttestor plugin, but disabled
		Plugin: workloadattestor.NewBuiltIn(&mock_workloadattestor.MockPlugin{}),
		Config: common_catalog.PluginConfig{
			PluginType: WorkloadAttestorType,
			Enabled:    false,
		},
	},
}

type AgentCatalogTestSuite struct {
	suite.Suite

	catalog *AgentCatalog

	// Logrus test hook for asserting
	// log messages, if desired
	logHook *test.Hook

	t    *testing.T
	ctrl *gomock.Controller
}

func (c *AgentCatalogTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(c.t)
	log, logHook := test.NewNullLogger()

	cat := &AgentCatalog{
		log: log,
	}

	c.catalog = cat
	c.ctrl = mockCtrl
	c.logHook = logHook
}

func (c *AgentCatalogTestSuite) TearDownTest() {
	c.ctrl.Finish()
}

func (c *AgentCatalogTestSuite) TestCategorizeNotEnoughTypes() {
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
			Plugin: &mock_workloadattestor.MockPlugin{},
			Config: common_catalog.PluginConfig{
				PluginType: WorkloadAttestorType,
				Enabled:    true,
			},
		},
	}
	comCatalog.EXPECT().Plugins().Return(onePlugin)
	err = c.catalog.categorize()
	c.Assert().Error(err)
	c.Assert().Contains(err.Error(), expectedErr)
}

func (c *AgentCatalogTestSuite) TestCategorize() {
	comCatalog := mock_catalog.NewMockCatalog(c.ctrl)
	c.catalog.com = comCatalog

	comCatalog.EXPECT().Plugins().Return(plugins)

	err := c.catalog.categorize()
	c.Assert().Nil(err)
}

func TestCatalog(t *testing.T) {
	suite.Run(t, new(AgentCatalogTestSuite))
}
