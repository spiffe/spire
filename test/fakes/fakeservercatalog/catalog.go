package fakeservercatalog

import (
	"fmt"

	common "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/bootstrapper"
	"github.com/spiffe/spire/proto/server/keymanager"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/spiffe/spire/proto/server/upstreamca"
)

type Catalog struct {
	dataStores    []*catalog.ManagedDataStore
	nodeAttestors []*catalog.ManagedNodeAttestor
	nodeResolvers []*catalog.ManagedNodeResolver
	upstreamCAs   []*catalog.ManagedUpstreamCA
	keyManagers   []*catalog.ManagedKeyManager
	eventHandlers []*catalog.ManagedBootstrapper
}

func New() *Catalog {
	return &Catalog{}
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
		c.AddNodeAttestorNamed(pluginName("nodeattestor", i), nodeAttestor)
	}
}

func (c *Catalog) AddNodeAttestorNamed(name string, nodeAttestor nodeattestor.NodeAttestor) {
	c.nodeAttestors = append(c.nodeAttestors, catalog.NewManagedNodeAttestor(
		nodeAttestor, common.PluginConfig{
			PluginName: name,
		}))
}

func (c *Catalog) NodeAttestors() []*catalog.ManagedNodeAttestor {
	return c.nodeAttestors
}

func (c *Catalog) SetNodeResolvers(nodeResolvers ...noderesolver.NodeResolver) {
	c.nodeResolvers = nil
	for i, nodeResolver := range nodeResolvers {
		c.AddNodeResolverNamed(pluginName("noderesolver", i), nodeResolver)
	}
}

func (c *Catalog) AddNodeResolverNamed(name string, nodeResolver noderesolver.NodeResolver) {
	c.nodeResolvers = append(c.nodeResolvers, catalog.NewManagedNodeResolver(
		nodeResolver, common.PluginConfig{
			PluginName: name,
		}))
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

func (c *Catalog) SetBootstrappers(eventHandlers ...bootstrapper.Bootstrapper) {
	c.eventHandlers = nil
	for i, eventHandlerr := range eventHandlers {
		c.eventHandlers = append(c.eventHandlers, catalog.NewManagedBootstrapper(
			eventHandlerr, common.PluginConfig{
				PluginName: pluginName("keymanager", i),
			}))
	}
}

func (c *Catalog) Bootstrappers() []*catalog.ManagedBootstrapper {
	return c.eventHandlers
}

func pluginName(kind string, i int) string {
	return fmt.Sprintf("fake_%s_%d", kind, i+1)
}
