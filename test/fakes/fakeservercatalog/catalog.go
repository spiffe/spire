package fakeservercatalog

import (
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
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

	upstreamAuthority upstreamauthority.UpstreamAuthority
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

func (c *Catalog) SetUpstreamAuthority(upstreamAuthority upstreamauthority.UpstreamAuthority) {
	if upstreamAuthority == nil {
		c.upstreamAuthority = nil
	} else {
		c.upstreamAuthority = upstreamAuthority
	}
}

// GetUpstreamAuthority obtains upstream authority from fake instead original catalog,
// it can be removed once upstream authority is properly loaded on catalog
func (c *Catalog) GetUpstreamAuthority() (upstreamauthority.UpstreamAuthority, bool) {
	return c.upstreamAuthority, c.upstreamAuthority != nil
}

func (c *Catalog) SetKeyManager(keyManager keymanager.KeyManager) {
	c.KeyManager = keyManager
}

func (c *Catalog) AddNotifier(notifier catalog.Notifier) {
	c.Notifiers = append(c.Notifiers, notifier)
}

func Notifier(name string, notifier notifier.Notifier) catalog.Notifier {
	return catalog.Notifier{
		PluginInfo: pluginInfo{name: name, typ: workloadattestor.Type},
		Notifier:   notifier,
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
