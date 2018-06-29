package fakeservercatalog

import (
	"fmt"

	common "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/spiffe/spire/proto/server/upstreamca"
)

type Catalog struct {
	cas           []*catalog.ManagedServerCA
	dataStores    []*catalog.ManagedDataStore
	nodeAttestors []*catalog.ManagedNodeAttestor
	nodeResolvers []*catalog.ManagedNodeResolver
	upstreamCAs   []*catalog.ManagedUpstreamCA
}

func New() *Catalog {
	return &Catalog{}
}

func (c *Catalog) SetCAs(cas ...ca.ServerCA) {
	c.cas = nil
	for i, ca := range cas {
		c.cas = append(c.cas, catalog.NewManagedServerCA(
			ca, common.PluginConfig{
				PluginName: pluginName("ca", i),
			}))
	}
}

func (c *Catalog) CAs() []*catalog.ManagedServerCA {
	return c.cas
}

func (c *Catalog) SetDataStores(dataStores ...datastore.DataStore) {
	c.dataStores = nil
	for i, dataStore := range dataStores {
		c.dataStores = append(c.dataStores, catalog.NewManagedDataStore(
			dataStore, common.PluginConfig{
				PluginName: pluginName("datastore", i),
			}))
	}
}

func (c *Catalog) DataStores() []*catalog.ManagedDataStore {
	return c.dataStores
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

func (c *Catalog) SetNodeResolvers(nodeResolvers ...noderesolver.NodeResolver) {
	c.nodeResolvers = nil
	for i, nodeResolver := range nodeResolvers {
		c.nodeResolvers = append(c.nodeResolvers, catalog.NewManagedNodeResolver(
			nodeResolver, common.PluginConfig{
				PluginName: pluginName("noderesolver", i),
			}))
	}
}

func (c *Catalog) NodeResolvers() []*catalog.ManagedNodeResolver {
	return c.nodeResolvers
}

func (c *Catalog) SetUpstreamCAs(upstreamCAs ...upstreamca.UpstreamCA) {
	c.upstreamCAs = nil
	for i, upstreamCA := range upstreamCAs {
		c.upstreamCAs = append(c.upstreamCAs, catalog.NewManagedUpstreamCA(
			upstreamCA, common.PluginConfig{
				PluginName: pluginName("upstreamca", i),
			}))
	}
}

func (c *Catalog) UpstreamCAs() []*catalog.ManagedUpstreamCA {
	return c.upstreamCAs
}

func pluginName(kind string, i int) string {
	return fmt.Sprintf("fake_%s_%d", kind, i+1)
}
