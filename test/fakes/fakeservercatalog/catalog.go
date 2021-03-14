package fakeservercatalog

import (
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
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

func (c *Catalog) AddNodeAttestor(nodeAttestor nodeattestor.NodeAttestor) {
	c.NodeAttestors[nodeAttestor.Name()] = nodeAttestor
}

func (c *Catalog) AddNodeResolverNamed(nodeResolver noderesolver.NodeResolver) {
	c.NodeResolvers[nodeResolver.Name()] = nodeResolver
}

func (c *Catalog) SetUpstreamAuthority(upstreamAuthority upstreamauthority.UpstreamAuthority) {
	c.UpstreamAuthority = upstreamAuthority
}

func (c *Catalog) SetKeyManager(keyManager keymanager.KeyManager) {
	c.KeyManager = keyManager
}

func (c *Catalog) AddNotifier(notifier notifier.Notifier) {
	c.Notifiers = append(c.Notifiers, notifier)
}
