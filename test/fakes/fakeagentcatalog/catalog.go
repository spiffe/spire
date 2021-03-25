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

func (c *Catalog) SetKeyManager(keyManager keymanager.KeyManager) {
	c.KeyManager = keyManager
}

func (c *Catalog) SetNodeAttestor(nodeAttestor nodeattestor.NodeAttestor) {
	c.NodeAttestor = nodeAttestor
}

func (c *Catalog) SetWorkloadAttestors(workloadAttestors ...workloadattestor.WorkloadAttestor) {
	c.WorkloadAttestors = workloadAttestors
}
