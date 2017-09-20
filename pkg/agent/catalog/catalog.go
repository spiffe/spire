package catalog

import (
	"fmt"

	"github.com/sirupsen/logrus"

	// Plugin interfaces
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/agent/workloadattestor"

	goplugin "github.com/hashicorp/go-plugin"
	common "github.com/spiffe/spire/pkg/common/catalog"
)

const (
	KeyManagerType       = "KeyManager"
	NodeAttestorType     = "NodeAttestor"
	WorkloadAttestorType = "WorkloadAttestor"
)

type Catalog interface {
	common.Catalog

	KeyManagers() ([]keymanager.KeyManager, error)
	NodeAttestors() ([]nodeattestor.NodeAttestor, error)
	WorkloadAttestors() ([]workloadattestor.WorkloadAttestor, error)
}

var (
	supportedPlugins = map[string]goplugin.Plugin{
		KeyManagerType:       &keymanager.KeyManagerPlugin{},
		NodeAttestorType:     &nodeattestor.NodeAttestorPlugin{},
		WorkloadAttestorType: &workloadattestor.WorkloadAttestorPlugin{},
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

func (c *catalog) KeyManagers() ([]keymanager.KeyManager, error) {
	var plugins []keymanager.KeyManager
	for _, p := range c.com.Plugins() {
		if p.Config.PluginType == KeyManagerType {
			plugin, ok := p.Plugin.(keymanager.KeyManager)
			if !ok {
				return nil, fmt.Errorf("Plugin %s does not adhere to keymanager interface", p.Config.PluginName)
			}

			plugins = append(plugins, plugin)
		}
	}

	return plugins, nil
}

func (c *catalog) NodeAttestors() ([]nodeattestor.NodeAttestor, error) {
	var plugins []nodeattestor.NodeAttestor
	for _, p := range c.com.Plugins() {
		if p.Config.PluginType == NodeAttestorType {
			plugin, ok := p.Plugin.(nodeattestor.NodeAttestor)
			if !ok {
				return nil, fmt.Errorf("Plugin %s does not adhere to node attestor interface", p.Config.PluginName)
			}

			plugins = append(plugins, plugin)
		}
	}

	return plugins, nil
}

func (c *catalog) WorkloadAttestors() ([]workloadattestor.WorkloadAttestor, error) {
	var plugins []workloadattestor.WorkloadAttestor
	for _, p := range c.com.Plugins() {
		if p.Config.PluginType == WorkloadAttestorType {
			plugin, ok := p.Plugin.(workloadattestor.WorkloadAttestor)
			if !ok {
				return nil, fmt.Errorf("Plugin %s does not adhere to workload attestor interface", p.Config.PluginName)
			}

			plugins = append(plugins, plugin)
		}
	}

	return plugins, nil
}
