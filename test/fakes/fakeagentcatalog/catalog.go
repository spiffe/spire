package fakeagentcatalog

import (
	"fmt"

	"github.com/spiffe/spire/pkg/agent/catalog"
	common "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
)

type Catalog struct {
	keyManagers       []*catalog.ManagedKeyManager
	nodeAttestors     []*catalog.ManagedNodeAttestor
	workloadAttestors []*catalog.ManagedWorkloadAttestor
}

func New() *Catalog {
	return &Catalog{}
}

func (c *Catalog) SetKeyManagers(keyManagers ...keymanager.KeyManager) {
	c.keyManagers = nil
	for i, keyManager := range keyManagers {
		c.keyManagers = append(c.keyManagers, catalog.NewManagedKeyManager(
			keyManager, common.PluginConfig{
				PluginName: pluginName("keymanager", i),
			}))
	}
}

func (c *Catalog) KeyManagers() []*catalog.ManagedKeyManager {
	return c.keyManagers
}

func (c *Catalog) SetNodeAttestors(nodeAttestors ...nodeattestor.NodeAttestor) {
	c.nodeAttestors = nil
	for i, nodeAttestor := range nodeAttestors {
		c.nodeAttestors = append(c.nodeAttestors, catalog.NewManagedNodeAttestor(
			nodeAttestor, common.PluginConfig{
				PluginName: pluginName("nodeattestor", i),
			}))
	}
}

func (c *Catalog) NodeAttestors() []*catalog.ManagedNodeAttestor {
	return c.nodeAttestors
}

func (c *Catalog) SetWorkloadAttestors(workloadAttestors ...workloadattestor.WorkloadAttestor) {
	c.workloadAttestors = nil
	for i, workloadAttestor := range workloadAttestors {
		c.workloadAttestors = append(c.workloadAttestors, catalog.NewManagedWorkloadAttestor(
			workloadAttestor, common.PluginConfig{
				PluginName: pluginName("workloadattestor", i),
			}))
	}
}

func (c *Catalog) WorkloadAttestors() []*catalog.ManagedWorkloadAttestor {
	return c.workloadAttestors
}

func pluginName(kind string, i int) string {
	return fmt.Sprintf("fake_%s_%d", kind, i+1)
}
