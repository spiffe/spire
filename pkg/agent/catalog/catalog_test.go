package catalog

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus/hooks/test"
	common_catalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/test/mock/common/catalog"
	"github.com/spiffe/spire/test/mock/proto/agent/keymanager"
	"github.com/spiffe/spire/test/mock/proto/agent/nodeattestor"
	"github.com/spiffe/spire/test/mock/proto/agent/workloadattestor"
	"github.com/stretchr/testify/suite"
)

type AgentCatalogTestSuite struct {
	suite.Suite

	catalog *catalog

	// Logrus test hook for asserting
	// log messages, if desired
	logHook *test.Hook

	t    *testing.T
	ctrl *gomock.Controller
}

func (c *AgentCatalogTestSuite) SetupTest() {
	mockCtrl := gomock.NewController(c.t)
	_, logHook := test.NewNullLogger()

	cat := &catalog{}

	c.catalog = cat
	c.ctrl = mockCtrl
	c.logHook = logHook
}

func (c *AgentCatalogTestSuite) TeardownTest() {
	c.ctrl.Finish()
}

func (c *AgentCatalogTestSuite) TestCategorizeNotEnoughTypes() {
	comCatalog := mock_catalog.NewMockCatalog(c.ctrl)
	c.catalog.com = comCatalog

	plugins := []*common_catalog.ManagedPlugin{
		&common_catalog.ManagedPlugin{
			Plugin: &mock_workloadattestor.MockWorkloadAttestor{},
			Config: common_catalog.PluginConfig{
				PluginType: WorkloadAttestorType,
			},
		},
	}
	comCatalog.EXPECT().Plugins().Return(plugins)

	err := c.catalog.categorize()
	c.Assert().Error(err)
	c.Assert().Contains(err.Error(), "At least one plugin of type")
}

func (c *AgentCatalogTestSuite) TestCategorize() {
	comCatalog := mock_catalog.NewMockCatalog(c.ctrl)
	c.catalog.com = comCatalog

	plugins := []*common_catalog.ManagedPlugin{
		&common_catalog.ManagedPlugin{
			Plugin: &mock_keymanager.MockKeyManager{},
			Config: common_catalog.PluginConfig{
				PluginType: KeyManagerType,
			},
		},
		&common_catalog.ManagedPlugin{
			Plugin: &mock_nodeattestor.MockNodeAttestor{},
			Config: common_catalog.PluginConfig{
				PluginType: NodeAttestorType,
			},
		},
		&common_catalog.ManagedPlugin{
			Plugin: &mock_workloadattestor.MockWorkloadAttestor{},
			Config: common_catalog.PluginConfig{
				PluginType: WorkloadAttestorType,
			},
		},
	}
	comCatalog.EXPECT().Plugins().Return(plugins)

	err := c.catalog.categorize()
	c.Assert().Nil(err)
}

func TestCatalog(t *testing.T) {
	suite.Run(t, new(AgentCatalogTestSuite))
}
