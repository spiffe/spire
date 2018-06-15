package catalog

import (
	"context"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/plugin/datastore/sql"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/aws"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/gcp"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/jointoken"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver/noop"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/spiffe/spire/proto/server/upstreamca"

	goplugin "github.com/hashicorp/go-plugin"
	common "github.com/spiffe/spire/pkg/common/catalog"
	ca_memory "github.com/spiffe/spire/pkg/server/plugin/ca/memory"
	upca_disk "github.com/spiffe/spire/pkg/server/plugin/upstreamca/disk"
)

const (
	CAType           = "ServerCA"
	DataStoreType    = "DataStore"
	NodeAttestorType = "NodeAttestor"
	NodeResolverType = "NodeResolver"
	UpstreamCAType   = "UpstreamCA"
)

type Catalog interface {
	common.Catalog

	CAs() []ca.ServerCa
	DataStores() []datastore.DataStore
	NodeAttestors() []nodeattestor.NodeAttestor
	NodeResolvers() []noderesolver.NodeResolver
	UpstreamCAs() []upstreamca.UpstreamCa
}

var (
	supportedPlugins = map[string]goplugin.Plugin{
		CAType:           &ca.ServerCaPlugin{},
		DataStoreType:    &datastore.DataStorePlugin{},
		NodeAttestorType: &nodeattestor.NodeAttestorPlugin{},
		NodeResolverType: &noderesolver.NodeResolverPlugin{},
		UpstreamCAType:   &upstreamca.UpstreamCaPlugin{},
	}

	builtinPlugins = common.BuiltinPluginMap{
		CAType: {
			"memory": ca_memory.NewWithDefault(),
		},
		DataStoreType: {
			"sql": sql.New(),
		},
		NodeAttestorType: {
			"aws_iid":                     aws.NewIID(),
			"join_token":                  jointoken.New(),
			"gcp_iit": gcp.NewInstanceIdentityToken(),
		},
		NodeResolverType: {
			"noop": noop.New(),
		},
		UpstreamCAType: {
			"disk": upca_disk.New(),
		},
	}
)

type Config struct {
	PluginConfigs common.PluginConfigMap
	Log           logrus.FieldLogger
}

type catalog struct {
	com common.Catalog
	m   *sync.RWMutex
	log logrus.FieldLogger

	caPlugins           []ca.ServerCa
	dataStorePlugins    []datastore.DataStore
	nodeAttestorPlugins []nodeattestor.NodeAttestor
	nodeResolverPlugins []noderesolver.NodeResolver
	upstreamCAPlugins   []upstreamca.UpstreamCa
}

func New(c *Config) Catalog {
	commonConfig := &common.Config{
		PluginConfigs:    c.PluginConfigs,
		SupportedPlugins: supportedPlugins,
		BuiltinPlugins:   builtinPlugins,
		Log:              c.Log,
	}

	return &catalog{
		log: c.Log,
		com: common.New(commonConfig),
		m:   new(sync.RWMutex),
	}
}

func (c *catalog) Run(ctx context.Context) error {
	c.m.Lock()
	defer c.m.Unlock()

	err := c.com.Run(ctx)
	if err != nil {
		return err
	}

	return c.categorize()
}

func (c *catalog) Stop() {
	c.m.Lock()
	defer c.m.Unlock()

	c.com.Stop()
	c.reset()

	return
}

func (c *catalog) Reload(ctx context.Context) error {
	c.m.Lock()
	defer c.m.Unlock()

	err := c.com.Reload(ctx)
	if err != nil {
		return err
	}

	return c.categorize()
}

func (c *catalog) Plugins() []*common.ManagedPlugin {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.com.Plugins()
}

func (c *catalog) Find(plugin common.Plugin) *common.ManagedPlugin {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.com.Find(plugin)
}

func (c *catalog) CAs() []ca.ServerCa {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.caPlugins
}

func (c *catalog) DataStores() []datastore.DataStore {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.dataStorePlugins
}

func (c *catalog) NodeAttestors() []nodeattestor.NodeAttestor {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.nodeAttestorPlugins
}

func (c *catalog) NodeResolvers() []noderesolver.NodeResolver {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.nodeResolverPlugins
}

func (c *catalog) UpstreamCAs() []upstreamca.UpstreamCa {
	c.m.RLock()
	defer c.m.RUnlock()

	return c.upstreamCAPlugins
}

// categorize iterates over all managed plugins and casts them into their
// respective client types. This method is called during Run and Reload
// to prevent the consumer from having to check for errors when fetching
// a client from the catalog
func (c *catalog) categorize() error {
	c.reset()

	for _, p := range c.com.Plugins() {
		if !p.Config.Enabled {
			c.log.Debugf("%s plugin %s is disabled and will not be categorized", p.Config.PluginType, p.Config.PluginName)
			continue
		}

		switch p.Config.PluginType {
		case CAType:
			pl, ok := p.Plugin.(ca.ServerCa)
			if !ok {
				return fmt.Errorf("Plugin %s does not adhere to CA interface", p.Config.PluginName)
			}
			c.caPlugins = append(c.caPlugins, pl)
		case DataStoreType:
			pl, ok := p.Plugin.(datastore.DataStore)
			if !ok {
				return fmt.Errorf("Plugin %s does not adhere to DataStore interface", p.Config.PluginName)
			}
			c.dataStorePlugins = append(c.dataStorePlugins, pl)
		case NodeAttestorType:
			pl, ok := p.Plugin.(nodeattestor.NodeAttestor)
			if !ok {
				return fmt.Errorf("Plugin %s does not adhere to NodeAttestor interface", p.Config.PluginName)
			}
			c.nodeAttestorPlugins = append(c.nodeAttestorPlugins, pl)
		case NodeResolverType:
			pl, ok := p.Plugin.(noderesolver.NodeResolver)
			if !ok {
				return fmt.Errorf("Plugin %s does not adhere to NodeResolver interface", p.Config.PluginName)
			}
			c.nodeResolverPlugins = append(c.nodeResolverPlugins, pl)
		case UpstreamCAType:
			pl, ok := p.Plugin.(upstreamca.UpstreamCa)
			if !ok {
				return fmt.Errorf("Plugin %s does not adhere to UpstreamCa interface", p.Config.PluginName)
			}
			c.upstreamCAPlugins = append(c.upstreamCAPlugins, pl)
		default:
			return fmt.Errorf("Unsupported plugin type %s", p.Config.PluginType)
		}
	}

	// Guarantee we have at least one of each type
	pluginCount := map[string]int{}
	pluginCount[CAType] = len(c.caPlugins)
	pluginCount[DataStoreType] = len(c.dataStorePlugins)
	pluginCount[NodeAttestorType] = len(c.nodeAttestorPlugins)
	pluginCount[NodeResolverType] = len(c.nodeResolverPlugins)
	pluginCount[UpstreamCAType] = len(c.upstreamCAPlugins)
	for t, c := range pluginCount {
		if c < 1 {
			return fmt.Errorf("At least one plugin of type %s is required", t)
		}
	}

	return nil
}

func (c *catalog) reset() {
	c.caPlugins = nil
	c.dataStorePlugins = nil
	c.nodeAttestorPlugins = nil
	c.nodeResolverPlugins = nil
	c.upstreamCAPlugins = nil
}
