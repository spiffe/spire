package catalog

import (
	"context"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/plugin/bootstrapper/k8sbootstrapper"
	"github.com/spiffe/spire/pkg/server/plugin/datastore/sql"
	aws_na "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/aws"
	azure_na "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/azure"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/gcp"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/jointoken"
	k8s_na_psat "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8s/psat"
	k8s_na_sat "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8s/sat"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/x509pop"
	aws_nr "github.com/spiffe/spire/pkg/server/plugin/noderesolver/aws"
	azure_nr "github.com/spiffe/spire/pkg/server/plugin/noderesolver/azure"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver/noop"
	"github.com/spiffe/spire/proto/server/bootstrapper"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/keymanager"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/spiffe/spire/proto/server/upstreamca"

	goplugin "github.com/hashicorp/go-plugin"
	common "github.com/spiffe/spire/pkg/common/catalog"
	keymanager_disk "github.com/spiffe/spire/pkg/server/plugin/keymanager/disk"
	keymanager_memory "github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	upstreamca_aws "github.com/spiffe/spire/pkg/server/plugin/upstreamca/awssecret"
	upstreamca_disk "github.com/spiffe/spire/pkg/server/plugin/upstreamca/disk"
)

const (
	DataStoreType    = "DataStore"
	NodeAttestorType = "NodeAttestor"
	NodeResolverType = "NodeResolver"
	UpstreamCAType   = "UpstreamCA"
	KeyManagerType   = "KeyManager"
	BootstrapperType = "Bootstrapper"
)

type Catalog interface {
	DataStores() []*ManagedDataStore
	NodeAttestors() []*ManagedNodeAttestor
	NodeResolvers() []*ManagedNodeResolver
	UpstreamCAs() []*ManagedUpstreamCA
	KeyManagers() []*ManagedKeyManager
	Bootstrappers() []*ManagedBootstrapper
}

var (
	supportedPlugins = map[string]goplugin.Plugin{
		DataStoreType:    &datastore.GRPCPlugin{},
		NodeAttestorType: &nodeattestor.GRPCPlugin{},
		NodeResolverType: &noderesolver.GRPCPlugin{},
		UpstreamCAType:   &upstreamca.GRPCPlugin{},
		KeyManagerType:   &keymanager.GRPCPlugin{},
		BootstrapperType: &bootstrapper.GRPCPlugin{},
	}

	builtinPlugins = common.BuiltinPluginMap{
		DataStoreType: {
			"sql": datastore.NewBuiltIn(sql.New()),
		},
		NodeAttestorType: {
			"aws_iid":    nodeattestor.NewBuiltIn(aws_na.NewIIDPlugin()),
			"join_token": nodeattestor.NewBuiltIn(jointoken.New()),
			"gcp_iit":    nodeattestor.NewBuiltIn(gcp.NewIITAttestorPlugin()),
			"x509pop":    nodeattestor.NewBuiltIn(x509pop.New()),
			"azure_msi":  nodeattestor.NewBuiltIn(azure_na.NewMSIAttestorPlugin()),
			"k8s_sat":    nodeattestor.NewBuiltIn(k8s_na_sat.NewAttestorPlugin()),
			"k8s_psat":   nodeattestor.NewBuiltIn(k8s_na_psat.NewAttestorPlugin()),
		},
		NodeResolverType: {
			"noop":      noderesolver.NewBuiltIn(noop.New()),
			"aws_iid":   noderesolver.NewBuiltIn(aws_nr.NewIIDResolverPlugin()),
			"azure_msi": noderesolver.NewBuiltIn(azure_nr.NewMSIResolverPlugin()),
		},
		UpstreamCAType: {
			"disk":      upstreamca.NewBuiltIn(upstreamca_disk.New()),
			"awssecret": upstreamca.NewBuiltIn(upstreamca_aws.New()),
		},
		KeyManagerType: {
			"disk":   keymanager.NewBuiltIn(keymanager_disk.New()),
			"memory": keymanager.NewBuiltIn(keymanager_memory.New()),
		},
		BootstrapperType: {
			"k8s_bootstrapper": bootstrapper.NewBuiltIn(k8sbootstrapper.New()),
		},
	}
)

type Config struct {
	GlobalConfig  *common.GlobalConfig
	PluginConfigs common.PluginConfigMap
	Log           logrus.FieldLogger
}

type ServerCatalog struct {
	com common.Catalog
	m   sync.RWMutex
	log logrus.FieldLogger

	dataStorePlugins    []*ManagedDataStore
	nodeAttestorPlugins []*ManagedNodeAttestor
	nodeResolverPlugins []*ManagedNodeResolver
	upstreamCAPlugins   []*ManagedUpstreamCA
	keyManagerPlugins   []*ManagedKeyManager
	bootstrapperPlugins []*ManagedBootstrapper
}

func New(c *Config) *ServerCatalog {
	commonConfig := &common.Config{
		GlobalConfig:     c.GlobalConfig,
		PluginConfigs:    c.PluginConfigs,
		SupportedPlugins: supportedPlugins,
		BuiltinPlugins:   builtinPlugins,
		Log:              c.Log,
	}

	return &ServerCatalog{
		log: c.Log,
		com: common.New(commonConfig),
	}
}

func (c *ServerCatalog) Run(ctx context.Context) error {
	c.m.Lock()
	defer c.m.Unlock()

	err := c.com.Run(ctx)
	if err != nil {
		return err
	}

	return c.categorize()
}

func (c *ServerCatalog) Stop() {
	c.m.Lock()
	defer c.m.Unlock()

	c.com.Stop()
	c.reset()

	return
}

func (c *ServerCatalog) Reload(ctx context.Context) error {
	c.m.Lock()
	defer c.m.Unlock()

	err := c.com.Reload(ctx)
	if err != nil {
		return err
	}

	return c.categorize()
}

func (c *ServerCatalog) DataStores() []*ManagedDataStore {
	c.m.RLock()
	defer c.m.RUnlock()

	return append([]*ManagedDataStore(nil), c.dataStorePlugins...)
}

func (c *ServerCatalog) NodeAttestors() []*ManagedNodeAttestor {
	c.m.RLock()
	defer c.m.RUnlock()

	return append([]*ManagedNodeAttestor(nil), c.nodeAttestorPlugins...)
}

func (c *ServerCatalog) NodeResolvers() []*ManagedNodeResolver {
	c.m.RLock()
	defer c.m.RUnlock()

	return append([]*ManagedNodeResolver(nil), c.nodeResolverPlugins...)
}

func (c *ServerCatalog) UpstreamCAs() []*ManagedUpstreamCA {
	c.m.RLock()
	defer c.m.RUnlock()

	return append([]*ManagedUpstreamCA(nil), c.upstreamCAPlugins...)
}

func (c *ServerCatalog) KeyManagers() []*ManagedKeyManager {
	c.m.RLock()
	defer c.m.RUnlock()

	return append([]*ManagedKeyManager(nil), c.keyManagerPlugins...)
}

func (c *ServerCatalog) Bootstrappers() []*ManagedBootstrapper {
	c.m.RLock()
	defer c.m.RUnlock()

	return append([]*ManagedBootstrapper(nil), c.bootstrapperPlugins...)
}

// categorize iterates over all managed plugins and casts them into their
// respective client types. This method is called during Run and Reload
// to prevent the consumer from having to check for errors when fetching
// a client from the catalog
func (c *ServerCatalog) categorize() error {
	c.reset()

	for _, p := range c.com.Plugins() {
		if !p.Config.Enabled {
			c.log.Debugf("%s plugin %s is disabled and will not be categorized", p.Config.PluginType, p.Config.PluginName)
			continue
		}

		switch p.Config.PluginType {
		case DataStoreType:
			pl, ok := p.Plugin.(datastore.DataStore)
			if !ok {
				return fmt.Errorf("Plugin %s does not adhere to DataStore interface", p.Config.PluginName)
			}
			c.dataStorePlugins = append(c.dataStorePlugins, NewManagedDataStore(pl, p.Config))
		case NodeAttestorType:
			pl, ok := p.Plugin.(nodeattestor.NodeAttestor)
			if !ok {
				return fmt.Errorf("Plugin %s (%T) does not adhere to NodeAttestor interface", p.Config.PluginName, p.Plugin)
			}
			c.nodeAttestorPlugins = append(c.nodeAttestorPlugins, NewManagedNodeAttestor(pl, p.Config))
		case NodeResolverType:
			pl, ok := p.Plugin.(noderesolver.NodeResolver)
			if !ok {
				return fmt.Errorf("Plugin %s does not adhere to NodeResolver interface", p.Config.PluginName)
			}
			c.nodeResolverPlugins = append(c.nodeResolverPlugins, NewManagedNodeResolver(pl, p.Config))
		case UpstreamCAType:
			pl, ok := p.Plugin.(upstreamca.UpstreamCA)
			if !ok {
				return fmt.Errorf("Plugin %s does not adhere to UpstreamCA interface", p.Config.PluginName)
			}
			c.upstreamCAPlugins = append(c.upstreamCAPlugins, NewManagedUpstreamCA(pl, p.Config))
		case KeyManagerType:
			pl, ok := p.Plugin.(keymanager.KeyManager)
			if !ok {
				return fmt.Errorf("Plugin %s does not adhere to KeyManager interface", p.Config.PluginName)
			}
			c.keyManagerPlugins = append(c.keyManagerPlugins, NewManagedKeyManager(pl, p.Config))
		case BootstrapperType:
			pl, ok := p.Plugin.(bootstrapper.Bootstrapper)
			if !ok {
				return fmt.Errorf("Plugin %s does not adhere to Bootstrapper interface", p.Config.PluginName)
			}
			c.bootstrapperPlugins = append(c.bootstrapperPlugins, NewManagedBootstrapper(pl, p.Config))
		default:
			return fmt.Errorf("Unsupported plugin type %s", p.Config.PluginType)
		}
	}

	// Guarantee we have at least one of each type
	pluginCount := map[string]int{}
	pluginCount[DataStoreType] = len(c.dataStorePlugins)
	pluginCount[NodeAttestorType] = len(c.nodeAttestorPlugins)
	pluginCount[NodeResolverType] = len(c.nodeResolverPlugins)
	pluginCount[KeyManagerType] = len(c.keyManagerPlugins)
	for t, c := range pluginCount {
		if c < 1 {
			return fmt.Errorf("At least one plugin of type %s is required", t)
		}
	}
	if len(c.bootstrapperPlugins) > 1 {
		return fmt.Errorf("Only one Bootstrapper plugin can be enabled.")
	}

	return nil
}

func (c *ServerCatalog) reset() {
	c.dataStorePlugins = nil
	c.nodeAttestorPlugins = nil
	c.nodeResolverPlugins = nil
	c.upstreamCAPlugins = nil
	c.keyManagerPlugins = nil
}
