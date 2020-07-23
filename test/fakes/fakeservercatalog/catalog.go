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
	c.DataStore = catalog.DataStore{
		PluginInfo: pluginInfo{name: "fake", typ: datastore.Type},
		DataStore:  dataStore,
	}
}

func (c *Catalog) AddNodeAttestorNamed(name string, nodeAttestor nodeattestor.NodeAttestor) {
	c.NodeAttestors[name] = nodeAttestor
}

func (c *Catalog) AddNodeResolverNamed(name string, nodeResolver noderesolver.NodeResolver) {
	c.NodeResolvers[name] = nodeResolver
}

func (c *Catalog) SetUpstreamAuthority(upstreamAuthority *catalog.UpstreamAuthority) {
	c.UpstreamAuthority = upstreamAuthority
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

func UpstreamAuthority(name string, ua upstreamauthority.UpstreamAuthority) *catalog.UpstreamAuthority {
	return &catalog.UpstreamAuthority{
		PluginInfo:        pluginInfo{name: name},
		UpstreamAuthority: ua,
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

func (pi pluginInfo) BuiltIn() bool {
	return true
}
