package catalog

import (
	"fmt"

	"github.com/sirupsen/logrus"

	// Plugin interfaces
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/nodeattestor"
	"github.com/spiffe/spire/pkg/server/noderesolver"
	"github.com/spiffe/spire/pkg/server/upstreamca"

	goplugin "github.com/hashicorp/go-plugin"
	common "github.com/spiffe/spire/pkg/common/catalog"
)

const (
	CAType           = "ControlPlaneCA"
	DataStoreType    = "DataStore"
	NodeAttestorType = "NodeAttestor"
	NodeResolverType = "NodeResolver"
	UpstreamCAType   = "UpstreamCA"
)

type Catalog interface {
	common.Catalog

	CAs() ([]*ca.ControlPlaneCa, error)
	DataStores() ([]*datastore.DataStore, error)
	NodeAttestors() ([]*nodeattestor.NodeAttestor, error)
	NodeResolvers() ([]*noderesolver.NodeResolver, error)
	UpstreamCAs() ([]*upstreamca.UpstreamCa, error)
}

var (
	supportedPlugins = map[string]goplugin.Plugin{
		CAType:           &ca.ControlPlaneCaPlugin{},
		DataStoreType:    &datastore.DataStorePlugin{},
		NodeAttestorType: &nodeattestor.NodeAttestorPlugin{},
		NodeResolverType: &noderesolver.NodeResolverPlugin{},
		UpstreamCAType:   &upstreamca.UpstreamCaPlugin{},
	}
)

type Config struct {
	// Directory in which plugin config files
	// reside
	ConfigDir string

	Log logrus.FieldLogger
}

type catalog struct {
	com common.Catalog
}

func New(c *Config) Catalog {
	commonConfig := &common.Config{
		ConfigDir:        c.ConfigDir,
		SupportedPlugins: supportedPlugins,
		Log:              c.Log,
	}

	return &catalog{com: common.New(commonConfig)}
}

func (c *catalog) Run() error {
	return c.com.Run()
}

func (c *catalog) Stop() {
	c.com.Stop()
	return
}

func (c *catalog) Reload() error {
	return c.com.Reload()
}

func (c *catalog) Plugins() []*common.ManagedPlugin {
	return c.com.Plugins()
}

func (c *catalog) CAs() ([]*ca.ControlPlaneCa, error) {
	var plugins []*ca.ControlPlaneCa
	for _, p := range c.com.Plugins() {
		if p.Config.PluginType == CAType {
			plugin, ok := p.Plugin.(ca.ControlPlaneCa)
			if !ok {
				return nil, fmt.Errorf("Plugin %s does not adhere to CA interface", p.Config.PluginName)
			}

			plugins = append(plugins, &plugin)
		}
	}

	return plugins, nil
}

func (c *catalog) DataStores() ([]*datastore.DataStore, error) {
	var plugins []*datastore.DataStore
	for _, p := range c.com.Plugins() {
		if p.Config.PluginType == DataStoreType {
			plugin, ok := p.Plugin.(datastore.DataStore)
			if !ok {
				return nil, fmt.Errorf("Plugin %s does not adhere to data store interface", p.Config.PluginName)
			}

			plugins = append(plugins, &plugin)
		}
	}

	return plugins, nil
}

func (c *catalog) NodeAttestors() ([]*nodeattestor.NodeAttestor, error) {
	var plugins []*nodeattestor.NodeAttestor
	for _, p := range c.com.Plugins() {
		if p.Config.PluginType == NodeAttestorType {
			plugin, ok := p.Plugin.(nodeattestor.NodeAttestor)
			if !ok {
				return nil, fmt.Errorf("Plugin %s does not adhere to node attestor interface", p.Config.PluginName)
			}

			plugins = append(plugins, &plugin)
		}
	}

	return plugins, nil
}

func (c *catalog) NodeResolvers() ([]*noderesolver.NodeResolver, error) {
	var plugins []*noderesolver.NodeResolver
	for _, p := range c.com.Plugins() {
		if p.Config.PluginType == NodeResolverType {
			plugin, ok := p.Plugin.(noderesolver.NodeResolver)
			if !ok {
				return nil, fmt.Errorf("Plugin %s does not adhere to node resolver interface", p.Config.PluginName)
			}

			plugins = append(plugins, &plugin)
		}
	}

	return plugins, nil
}

func (c *catalog) UpstreamCAs() ([]*upstreamca.UpstreamCa, error) {
	var plugins []*upstreamca.UpstreamCa
	for _, p := range c.com.Plugins() {
		if p.Config.PluginType == UpstreamCAType {
			plugin, ok := p.Plugin.(upstreamca.UpstreamCa)
			if !ok {
				return nil, fmt.Errorf("Plugin %s does not adhere to upstream CA interface", p.Config.PluginName)
			}

			plugins = append(plugins, &plugin)
		}
	}

	return plugins, nil
}
