package fakeservercatalog

import (
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/keymanager"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/spiffe/spire/proto/server/upstreamca"
)

type Catalog struct {
	catalog.Plugins
}

func New() *Catalog {
	return &Catalog{
		Plugins: catalog.Plugins{
			NodeAttestors: make(map[string]nodeattestor.NodeAttestor),
			NodeResolvers: make(map[string]noderesolver.NodeResolver),
		},
	}
}

func (c *Catalog) SetDataStore(dataStore datastore.DataStore) {
	c.DataStore = dataStore
}

func (c *Catalog) AddNodeAttestorNamed(name string, nodeAttestor nodeattestor.NodeAttestor) {
	c.NodeAttestors[name] = nodeAttestor
}

func (c *Catalog) AddNodeResolverNamed(name string, nodeResolver noderesolver.NodeResolver) {
	c.NodeResolvers[name] = nodeResolver
}

func (c *Catalog) SetUpstreamCA(upstreamCA upstreamca.UpstreamCA) {
	c.UpstreamCA = &upstreamCA
}

func (c *Catalog) SetKeyManager(keyManager keymanager.KeyManager) {
	c.KeyManager = keyManager
}
