package catalog

import (
	common "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/spiffe/spire/proto/server/upstreamca"
)

type ManagedServerCA struct {
	config common.PluginConfig
	ca.ServerCA
}

func NewManagedServerCA(p ca.ServerCA, config common.PluginConfig) *ManagedServerCA {
	return &ManagedServerCA{
		config:   config,
		ServerCA: p,
	}
}

func (p *ManagedServerCA) Config() common.PluginConfig {
	return p.config
}

type ManagedDataStore struct {
	config common.PluginConfig
	datastore.DataStore
}

func NewManagedDataStore(p datastore.DataStore, config common.PluginConfig) *ManagedDataStore {
	return &ManagedDataStore{
		config:    config,
		DataStore: p,
	}
}

func (p *ManagedDataStore) Config() common.PluginConfig {
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

type ManagedNodeResolver struct {
	config common.PluginConfig
	noderesolver.NodeResolver
}

func NewManagedNodeResolver(p noderesolver.NodeResolver, config common.PluginConfig) *ManagedNodeResolver {
	return &ManagedNodeResolver{
		config:       config,
		NodeResolver: p,
	}
}

func (p *ManagedNodeResolver) Config() common.PluginConfig {
	return p.config
}

type ManagedUpstreamCA struct {
	config common.PluginConfig
	upstreamca.UpstreamCA
}

func NewManagedUpstreamCA(p upstreamca.UpstreamCA, config common.PluginConfig) *ManagedUpstreamCA {
	return &ManagedUpstreamCA{
		config:     config,
		UpstreamCA: p,
	}
}

func (p *ManagedUpstreamCA) Config() common.PluginConfig {
	return p.config
}
