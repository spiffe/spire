package fakeagentcatalog

import (
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
)

type Catalog struct {
	catalog.Plugins
}

func New() *Catalog {
	return &Catalog{}
}

func (c *Catalog) SetKeyManager(keyManager catalog.KeyManager) {
	c.KeyManager = keyManager
}

func (c *Catalog) SetNodeAttestor(nodeAttestor catalog.NodeAttestor) {
	c.NodeAttestor = nodeAttestor
}

func (c *Catalog) SetWorkloadAttestors(workloadAttestors ...catalog.WorkloadAttestor) {
	c.WorkloadAttestors = workloadAttestors
}

func KeyManager(keyManager keymanager.KeyManager) catalog.KeyManager {
	return catalog.KeyManager{
		KeyManager: keyManager,
	}
}

func NodeAttestor(name string, nodeAttestor nodeattestor.NodeAttestor) catalog.NodeAttestor {
	return catalog.NodeAttestor{
		PluginInfo:   pluginInfo{name: name, typ: nodeattestor.Type},
		NodeAttestor: nodeAttestor,
	}
}

func WorkloadAttestor(name string, workloadAttestor workloadattestor.WorkloadAttestor) catalog.WorkloadAttestor {
	return catalog.WorkloadAttestor{
		PluginInfo:       pluginInfo{name: name, typ: workloadattestor.Type},
		WorkloadAttestor: workloadAttestor,
	}
}

type pluginInfo struct {
	name string
	typ  string
}

func (pi pluginInfo) Name() string {
	return pi.name
}

func (pi pluginInfo) Type() string {
	return pi.typ
}
