package catalog

import (
	"context"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/disk"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/memory"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/aws"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/gcp"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/jointoken"
	k8sna "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/k8s"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/x509pop"
	k8swa "github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/k8s"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/unix"
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
	KeyManagers() []*ManagedKeyManager
	NodeAttestors() []*ManagedNodeAttestor
	WorkloadAttestors() []*ManagedWorkloadAttestor
}

var (
	supportedPlugins = map[string]goplugin.Plugin{
		KeyManagerType:       &keymanager.GRPCPlugin{},
		NodeAttestorType:     &nodeattestor.GRPCPlugin{},
		WorkloadAttestorType: &workloadattestor.GRPCPlugin{},
	}

	builtinPlugins = common.BuiltinPluginMap{
		KeyManagerType: {
			"disk":   keymanager.NewBuiltIn(disk.New()),
			"memory": keymanager.NewBuiltIn(memory.New()),
		},
		NodeAttestorType: {
			"aws_iid":    nodeattestor.NewBuiltIn(aws.NewIID()),
			"join_token": nodeattestor.NewBuiltIn(jointoken.New()),
			"gcp_iit":    nodeattestor.NewBuiltIn(gcp.NewIITAttestorPlugin()),
			"x509pop":    nodeattestor.NewBuiltIn(x509pop.New()),
			"k8s":        nodeattestor.NewBuiltIn(k8sna.New()),
		},
		WorkloadAttestorType: {
			"k8s":  workloadattestor.NewBuiltIn(k8swa.New()),
			"unix": workloadattestor.NewBuiltIn(unix.New()),
		},
	}
)

type Config struct {
	PluginConfigs common.PluginConfigMap
	Log           logrus.FieldLogger
}

type AgentCatalog struct {
	com common.Catalog
	m   *sync.RWMutex
	log logrus.FieldLogger

	keyManagerPlugins       []*ManagedKeyManager
	nodeAttestorPlugins     []*ManagedNodeAttestor
	workloadAttestorPlugins []*ManagedWorkloadAttestor
}

func New(c *Config) *AgentCatalog {
	commonConfig := &common.Config{
		PluginConfigs:    c.PluginConfigs,
		SupportedPlugins: supportedPlugins,
		BuiltinPlugins:   builtinPlugins,
		Log:              c.Log,
	}

	return &AgentCatalog{
		log: c.Log,
		com: common.New(commonConfig),
		m:   new(sync.RWMutex),
	}
}

func (c *AgentCatalog) Run(ctx context.Context) error {
	c.m.Lock()
	defer c.m.Unlock()

	err := c.com.Run(ctx)
	if err != nil {
		return err
	}

	return c.categorize()
}

func (c *AgentCatalog) Stop() {
	c.m.Lock()
	defer c.m.Unlock()

	c.com.Stop()
	c.reset()

	return
}

func (c *AgentCatalog) Reload(ctx context.Context) error {
	c.m.Lock()
	defer c.m.Unlock()

	err := c.com.Reload(ctx)
	if err != nil {
		return err
	}

	return c.categorize()
}

func (c *AgentCatalog) KeyManagers() []*ManagedKeyManager {
	c.m.RLock()
	defer c.m.RUnlock()

	return append([]*ManagedKeyManager(nil), c.keyManagerPlugins...)
}

func (c *AgentCatalog) NodeAttestors() []*ManagedNodeAttestor {
	c.m.RLock()
	defer c.m.RUnlock()

	return append([]*ManagedNodeAttestor(nil), c.nodeAttestorPlugins...)
}

func (c *AgentCatalog) WorkloadAttestors() []*ManagedWorkloadAttestor {
	c.m.RLock()
	defer c.m.RUnlock()

	return append([]*ManagedWorkloadAttestor(nil), c.workloadAttestorPlugins...)
}

// categorize iterates over all managed plugins and casts them into their
// respective client types. This method is called during Run and Reload
// to prevent the consumer from having to check for errors when fetching
// a client from the catalog
func (c *AgentCatalog) categorize() error {
	c.reset()

	errMsg := "Plugin %s does not adhere to %s interface"
	for _, p := range c.com.Plugins() {
		if !p.Config.Enabled {
			c.log.Debugf("%s plugin %s is disabled and will not be categorized", p.Config.PluginType, p.Config.PluginName)
			continue
		}

		switch p.Config.PluginType {
		case KeyManagerType:
			pl, ok := p.Plugin.(keymanager.KeyManager)
			if !ok {
				return fmt.Errorf(errMsg, p.Config.PluginName, KeyManagerType)
			}
			c.keyManagerPlugins = append(c.keyManagerPlugins, NewManagedKeyManager(pl, p.Config))
		case NodeAttestorType:
			pl, ok := p.Plugin.(nodeattestor.NodeAttestor)
			if !ok {
				return fmt.Errorf(errMsg, p.Config.PluginName, NodeAttestorType)
			}
			c.nodeAttestorPlugins = append(c.nodeAttestorPlugins, NewManagedNodeAttestor(pl, p.Config))
		case WorkloadAttestorType:
			pl, ok := p.Plugin.(workloadattestor.WorkloadAttestor)
			if !ok {
				return fmt.Errorf(errMsg, p.Config.PluginName, WorkloadAttestorType)
			}
			c.workloadAttestorPlugins = append(c.workloadAttestorPlugins, NewManagedWorkloadAttestor(pl, p.Config))
		default:
			return fmt.Errorf("Unsupported plugin type %s", p.Config.PluginType)
		}
	}

	// Guarantee we have at least one of each type
	pluginCount := map[string]int{}
	pluginCount[KeyManagerType] = len(c.keyManagerPlugins)
	pluginCount[NodeAttestorType] = len(c.nodeAttestorPlugins)
	pluginCount[WorkloadAttestorType] = len(c.workloadAttestorPlugins)
	for t, c := range pluginCount {
		if c < 1 {
			return fmt.Errorf("At least one plugin of type %s is required", t)
		}
	}

	return nil
}

func (c *AgentCatalog) reset() {
	c.keyManagerPlugins = nil
	c.nodeAttestorPlugins = nil
	c.workloadAttestorPlugins = nil
}
