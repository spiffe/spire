package catalog

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/catalog"
	common_services "github.com/spiffe/spire/pkg/common/plugin/hostservices"
	"github.com/spiffe/spire/pkg/common/telemetry"
	datastore_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	ds_sql "github.com/spiffe/spire/pkg/server/plugin/datastore/sql"
	"github.com/spiffe/spire/pkg/server/plugin/hostservices"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	km_disk "github.com/spiffe/spire/pkg/server/plugin/keymanager/disk"
	km_memory "github.com/spiffe/spire/pkg/server/plugin/keymanager/memory"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	na_aws_iid "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/aws"
	na_azure_msi "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/azure"
	na_gcp_iit "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/gcp"
	na_join_token "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/jointoken"
	na_k8s_psat "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8s/psat"
	na_k8s_sat "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8s/sat"
	na_sshpop "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/sshpop"
	na_x509pop "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/x509pop"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	nr_aws_iid "github.com/spiffe/spire/pkg/server/plugin/noderesolver/aws"
	nr_azure_msi "github.com/spiffe/spire/pkg/server/plugin/noderesolver/azure"
	nr_noop "github.com/spiffe/spire/pkg/server/plugin/noderesolver/noop"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	no_gcs_bundle "github.com/spiffe/spire/pkg/server/plugin/notifier/gcsbundle"
	no_k8sbundle "github.com/spiffe/spire/pkg/server/plugin/notifier/k8sbundle"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	up_awspca "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/awspca"
	up_awssecret "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/awssecret"
	up_disk "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/disk"
	up_spire "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/spire"
	up_vault "github.com/spiffe/spire/pkg/server/plugin/upstreamauthority/vault"
)

var (
	builtIns = []catalog.Plugin{
		// DataStores
		ds_sql.BuiltIn(),
		// NodeAttestors
		na_aws_iid.BuiltIn(),
		na_gcp_iit.BuiltIn(),
		na_x509pop.BuiltIn(),
		na_sshpop.BuiltIn(),
		na_azure_msi.BuiltIn(),
		na_k8s_sat.BuiltIn(),
		na_k8s_psat.BuiltIn(),
		na_join_token.BuiltIn(),
		// NodeResolvers
		nr_noop.BuiltIn(),
		nr_aws_iid.BuiltIn(),
		nr_azure_msi.BuiltIn(),
		// UpstreamAuthorities
		up_awspca.BuiltIn(),
		up_awssecret.BuiltIn(),
		up_spire.BuiltIn(),
		up_disk.BuiltIn(),
		up_vault.BuiltIn(),
		// KeyManagers
		km_disk.BuiltIn(),
		km_memory.BuiltIn(),
		// Notifiers
		no_k8sbundle.BuiltIn(),
		no_gcs_bundle.BuiltIn(),
	}
)

type Catalog interface {
	GetDataStore() datastore.DataStore
	GetNodeAttestorNamed(name string) (nodeattestor.NodeAttestor, bool)
	GetNodeResolverNamed(name string) (noderesolver.NodeResolver, bool)
	GetKeyManager() keymanager.KeyManager
	GetNotifiers() []Notifier
	GetUpstreamAuthority() (*UpstreamAuthority, bool)
}

type GlobalConfig = catalog.GlobalConfig
type HCLPluginConfig = catalog.HCLPluginConfig
type HCLPluginConfigMap = catalog.HCLPluginConfigMap

func KnownPlugins() []catalog.PluginClient {
	return []catalog.PluginClient{
		datastore.PluginClient,
		nodeattestor.PluginClient,
		noderesolver.PluginClient,
		upstreamauthority.PluginClient,
		keymanager.PluginClient,
		notifier.PluginClient,
	}
}

func KnownServices() []catalog.ServiceClient {
	return []catalog.ServiceClient{}
}

func BuiltIns() []catalog.Plugin {
	return append([]catalog.Plugin(nil), builtIns...)
}

type DataStore struct {
	catalog.PluginInfo
	datastore.DataStore
}

type Notifier struct {
	catalog.PluginInfo
	notifier.Notifier
}

type UpstreamAuthority struct {
	catalog.PluginInfo
	upstreamauthority.UpstreamAuthority
}

type Plugins struct {
	DataStore         DataStore
	NodeAttestors     map[string]nodeattestor.NodeAttestor
	NodeResolvers     map[string]noderesolver.NodeResolver
	UpstreamAuthority *UpstreamAuthority
	KeyManager        keymanager.KeyManager
	Notifiers         []Notifier
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

func (p *Plugins) GetKeyManager() keymanager.KeyManager {
	return p.KeyManager
}

func (p *Plugins) GetNotifiers() []Notifier {
	return p.Notifiers
}

func (p *Plugins) GetUpstreamAuthority() (*UpstreamAuthority, bool) {
	return p.UpstreamAuthority, p.UpstreamAuthority != nil
}

type Config struct {
	Log          logrus.FieldLogger
	GlobalConfig GlobalConfig
	PluginConfig HCLPluginConfigMap

	Metrics          telemetry.Metrics
	IdentityProvider hostservices.IdentityProvider
	AgentStore       hostservices.AgentStore
	MetricsService   common_services.MetricsService
}

type Repository struct {
	Catalog
	catalog.Closer
}

func Load(ctx context.Context, config Config) (*Repository, error) {
	pluginConfigs, err := catalog.PluginConfigFromHCL(config.PluginConfig)
	if err != nil {
		return nil, err
	}

	p := new(Plugins)
	closer, err := catalog.Fill(ctx, catalog.Config{
		Log:           config.Log,
		GlobalConfig:  config.GlobalConfig,
		PluginConfig:  pluginConfigs,
		KnownPlugins:  KnownPlugins(),
		KnownServices: KnownServices(),
		BuiltIns:      BuiltIns(),
		HostServices: []catalog.HostServiceServer{
			hostservices.IdentityProviderHostServiceServer(config.IdentityProvider),
			hostservices.AgentStoreHostServiceServer(config.AgentStore),
			common_services.MetricsServiceHostServiceServer(config.MetricsService),
		},
	}, p)
	if err != nil {
		return nil, err
	}

	// The DataStore interface is no longer pluggable (see #1650).
	if !p.DataStore.BuiltIn() {
		return nil, fmt.Errorf("pluggability for the DataStore is deprecated; only the built-in SQL plugin is supported")
	}
	p.DataStore.DataStore = datastore_telemetry.WithMetrics(p.DataStore.DataStore, config.Metrics)

	return &Repository{
		Catalog: p,
		Closer:  closer,
	}, nil
}
