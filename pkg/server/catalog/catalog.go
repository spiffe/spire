package catalog

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/catalog"
	ds_sql "github.com/spiffe/spire/pkg/server/plugin/datastore/sql"
	km_disk "github.com/spiffe/spire/pkg/server/plugin/keymanager/disk"
	km_memory "github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	na_aws_iid "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/aws"
	na_azure_msi "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/azure"
	na_gcp_iit "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/gcp"
	na_join_token "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/jointoken"
	na_k8s_psat "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8s/psat"
	na_k8s_sat "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8s/sat"
	na_x509pop "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/x509pop"
	nr_aws_iid "github.com/spiffe/spire/pkg/server/plugin/noderesolver/aws"
	nr_azure_msi "github.com/spiffe/spire/pkg/server/plugin/noderesolver/azure"
	nr_noop "github.com/spiffe/spire/pkg/server/plugin/noderesolver/noop"
	up_awssecret "github.com/spiffe/spire/pkg/server/plugin/upstreamca/awssecret"
	up_disk "github.com/spiffe/spire/pkg/server/plugin/upstreamca/disk"
	"github.com/spiffe/spire/proto/server/datastore"
	"github.com/spiffe/spire/proto/server/keymanager"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/spiffe/spire/proto/server/noderesolver"
	"github.com/spiffe/spire/proto/server/upstreamca"
)

type Catalog interface {
	GetDataStore() datastore.DataStore
	GetNodeAttestorNamed(name string) (nodeattestor.NodeAttestor, bool)
	GetNodeResolverNamed(name string) (noderesolver.NodeResolver, bool)
	GetUpstreamCA() (upstreamca.UpstreamCA, bool)
	GetKeyManager() keymanager.KeyManager
}

type CatalogCloser struct {
	Catalog
	catalog.Closer
}

type GlobalConfig = catalog.GlobalConfig
type HCLPluginConfig = catalog.HCLPluginConfig
type HCLPluginConfigMap = catalog.HCLPluginConfigMap

func KnownPlugins() []catalog.PluginClient {
	return []catalog.PluginClient{
		datastore.PluginClient,
		nodeattestor.PluginClient,
		noderesolver.PluginClient,
		upstreamca.PluginClient,
		keymanager.PluginClient,
	}
}

func KnownServices() []catalog.ServiceClient {
	return []catalog.ServiceClient{}
}

func BuiltIns() []catalog.Plugin {
	return []catalog.Plugin{
		// DataStores
		ds_sql.BuiltIn(),
		// NodeAttestors
		na_aws_iid.BuiltIn(),
		na_gcp_iit.BuiltIn(),
		na_x509pop.BuiltIn(),
		na_azure_msi.BuiltIn(),
		na_k8s_sat.BuiltIn(),
		na_k8s_psat.BuiltIn(),
		na_join_token.BuiltIn(),
		// NodeResolvers
		nr_noop.BuiltIn(),
		nr_aws_iid.BuiltIn(),
		nr_azure_msi.BuiltIn(),
		// UpstreamCAs
		up_disk.BuiltIn(),
		up_awssecret.BuiltIn(),
		// KeyManagers
		km_disk.BuiltIn(),
		km_memory.BuiltIn(),
	}
}

type Plugins struct {
	DataStore     datastore.DataStore
	NodeAttestors map[string]nodeattestor.NodeAttestor
	NodeResolvers map[string]noderesolver.NodeResolver
	UpstreamCA    *upstreamca.UpstreamCA
	KeyManager    keymanager.KeyManager
}

var _ Catalog = (*Plugins)(nil)

func (p *Plugins) GetDataStore() datastore.DataStore {
	return p.DataStore
}

func (p *Plugins) GetNodeAttestorNamed(name string) (nodeattestor.NodeAttestor, bool) {
	n, ok := p.NodeAttestors[name]
	return n, ok
}

func (p *Plugins) GetNodeResolverNamed(name string) (noderesolver.NodeResolver, bool) {
	n, ok := p.NodeResolvers[name]
	return n, ok
}

func (p *Plugins) GetUpstreamCA() (upstreamca.UpstreamCA, bool) {
	if p.UpstreamCA != nil {
		return *p.UpstreamCA, true
	}
	return nil, false
}

func (p *Plugins) GetKeyManager() keymanager.KeyManager {
	return p.KeyManager
}

type Config struct {
	Log          logrus.FieldLogger
	GlobalConfig GlobalConfig
	PluginConfig HCLPluginConfigMap
	HostServices []catalog.HostServiceServer
}

func Load(ctx context.Context, config Config) (*CatalogCloser, error) {
	pluginConfig, err := catalog.PluginConfigFromHCL(config.PluginConfig)
	if err != nil {
		return nil, err
	}

	p := new(Plugins)
	closer, err := catalog.Fill(ctx, catalog.Config{
		Log:           config.Log,
		GlobalConfig:  config.GlobalConfig,
		PluginConfig:  pluginConfig,
		KnownPlugins:  KnownPlugins(),
		KnownServices: KnownServices(),
		BuiltIns:      BuiltIns(),
		HostServices:  config.HostServices,
	}, p)

	return &CatalogCloser{
		Catalog: p,
		Closer:  closer,
	}, nil
}
