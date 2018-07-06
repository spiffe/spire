package catalog

import (
	common "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/agent/keymanager"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/agent/workloadattestor"
)

type ManagedKeyManager struct {
	config common.PluginConfig
	keymanager.KeyManager
}

func NewManagedKeyManager(p keymanager.KeyManager, config common.PluginConfig) *ManagedKeyManager {
	return &ManagedKeyManager{
		config:     config,
		KeyManager: p,
	}
}

func (p *ManagedKeyManager) Config() common.PluginConfig {
	return p.config
}

type ManagedNodeAttestor struct {
	config common.PluginConfig
	nodeattestor.NodeAttestor
}

func NewManagedNodeAttestor(p nodeattestor.NodeAttestor, config common.PluginConfig) *ManagedNodeAttestor {
	return &ManagedNodeAttestor{
		config:       config,
		NodeAttestor: p,
	}
}

func (p *ManagedNodeAttestor) Config() common.PluginConfig {
	return p.config
}

type ManagedWorkloadAttestor struct {
	config common.PluginConfig
	workloadattestor.WorkloadAttestor
}

func NewManagedWorkloadAttestor(p workloadattestor.WorkloadAttestor, config common.PluginConfig) *ManagedWorkloadAttestor {
	return &ManagedWorkloadAttestor{
		config:           config,
		WorkloadAttestor: p,
	}
}

func (p *ManagedWorkloadAttestor) Config() common.PluginConfig {
	return p.config
}
