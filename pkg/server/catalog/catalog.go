package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	metricsv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/common/metrics/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/hostservice/metricsservice"
	"github.com/spiffe/spire/pkg/common/telemetry"
	ds_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server/datastore"
	km_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server/keymanager"
	"github.com/spiffe/spire/pkg/server/cache/dscache"
	"github.com/spiffe/spire/pkg/server/datastore"
	ds_sql "github.com/spiffe/spire/pkg/server/datastore/sqlstore"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	metricsv0 "github.com/spiffe/spire/proto/spire/hostservice/common/metrics/v0"
	agentstorev0 "github.com/spiffe/spire/proto/spire/hostservice/server/agentstore/v0"
	identityproviderv0 "github.com/spiffe/spire/proto/spire/hostservice/server/identityprovider/v0"
)

const (
	dataStoreType         = "DataStore"
	keyManagerType        = "KeyManager"
	nodeAttestorType      = "NodeAttestor"
	nodeResolverType      = "NodeResolver"
	notifierType          = "Notifier"
	upstreamAuthorityType = "UpstreamAuthority"
)

type Catalog interface {
	GetDataStore() datastore.DataStore
	GetNodeAttestorNamed(name string) (nodeattestor.NodeAttestor, bool)
	GetNodeResolverNamed(name string) (noderesolver.NodeResolver, bool)
	GetKeyManager() keymanager.KeyManager
	GetNotifiers() []notifier.Notifier
	GetUpstreamAuthority() (upstreamauthority.UpstreamAuthority, bool)
}

type HCLPluginConfigMap = catalog.HCLPluginConfigMap

type Config struct {
	Log          logrus.FieldLogger
	TrustDomain  spiffeid.TrustDomain
	PluginConfig HCLPluginConfigMap

	Metrics          telemetry.Metrics
	IdentityProvider identityproviderv0.IdentityProviderServer
	AgentStore       agentstorev0.AgentStoreServer
	MetricsService   metricsv0.MetricsServiceServer
	HealthChecker    health.Checker
}

type datastoreRepository struct{ datastore.Repository }

type Repository struct {
	datastoreRepository
	keyManagerRepository
	nodeAttestorRepository
	nodeResolverRepository
	notifierRepository
	upstreamAuthorityRepository
	io.Closer
}

func (repo *Repository) Plugins() map[string]catalog.PluginRepo {
	return map[string]catalog.PluginRepo{
		keyManagerType:        &repo.keyManagerRepository,
		nodeAttestorType:      &repo.nodeAttestorRepository,
		nodeResolverType:      &repo.nodeResolverRepository,
		notifierType:          &repo.notifierRepository,
		upstreamAuthorityType: &repo.upstreamAuthorityRepository,
	}
}

func (repo *Repository) Services() []catalog.ServiceRepo {
	return nil
}

func Load(ctx context.Context, config Config) (_ *Repository, err error) {
	// Strip out the Datastore plugin configuration and load the SQL plugin
	// directly. This allows us to bypass gRPC and get rid of response limits.
	dataStoreConfig := config.PluginConfig[dataStoreType]
	delete(config.PluginConfig, dataStoreType)
	dataStore, err := loadSQLDataStore(config.Log, dataStoreConfig)
	if err != nil {
		return nil, err
	}

	if noopConfig, ok := config.PluginConfig[nodeResolverType]["noop"]; ok && noopConfig.PluginCmd == "" {
		// TODO: remove in 1.1.0
		delete(config.PluginConfig[nodeResolverType], "noop")
		config.Log.Warn(`The "noop" NodeResolver is not required, is deprecated, and will be removed from a future release`)
	}

	pluginConfigs, err := catalog.PluginConfigsFromHCL(config.PluginConfig)
	if err != nil {
		return nil, err
	}

	repo := new(Repository)
	repo.Closer, err = catalog.Load(ctx, catalog.Config{
		Log: config.Log,
		CoreConfig: catalog.CoreConfig{
			TrustDomain: config.TrustDomain,
		},
		PluginConfigs: pluginConfigs,
		HostServices: []catalog.HostServiceServer{
			{
				ServiceServer: identityproviderv0.IdentityProviderServiceServer(config.IdentityProvider),
				LegacyType:    "IdentityProvider",
			},
			{
				ServiceServer: agentstorev0.AgentStoreServiceServer(config.AgentStore),
				LegacyType:    "AgentStore",
			},
			{
				ServiceServer: metricsv0.MetricsServiceServiceServer(metricsservice.V0(config.Metrics)),
				LegacyType:    "MetricsService",
			},
			{
				ServiceServer: metricsv1.MetricsServiceServer(metricsservice.V1(config.Metrics)),
			},
		},
	}, repo)
	if err != nil {
		return nil, err
	}

	_ = config.HealthChecker.AddCheck("catalog.datastore", &datastore.Health{
		DataStore: dataStore,
	})

	dataStore = ds_telemetry.WithMetrics(dataStore, config.Metrics)
	dataStore = dscache.New(dataStore, clock.New())

	repo.SetDataStore(dataStore)
	repo.SetKeyManager(km_telemetry.WithMetrics(repo.GetKeyManager(), config.Metrics))

	return repo, nil
}

func loadSQLDataStore(log logrus.FieldLogger, datastoreConfig map[string]catalog.HCLPluginConfig) (datastore.DataStore, error) {
	switch {
	case len(datastoreConfig) == 0:
		return nil, errors.New("expecting a DataStore plugin")
	case len(datastoreConfig) > 1:
		return nil, errors.New("only one DataStore plugin is allowed")
	}

	sqlHCLConfig, ok := datastoreConfig[ds_sql.PluginName]
	if !ok {
		return nil, fmt.Errorf("pluggability for the DataStore is deprecated; only the built-in %q plugin is supported", ds_sql.PluginName)
	}

	sqlConfig, err := catalog.PluginConfigFromHCL(dataStoreType, ds_sql.PluginName, sqlHCLConfig)
	if err != nil {
		return nil, err
	}

	// Is the plugin external?
	if sqlConfig.Path != "" {
		return nil, fmt.Errorf("pluggability for the DataStore is deprecated; only the built-in %q plugin is supported", ds_sql.PluginName)
	}

	ds := ds_sql.New(log.WithField(telemetry.SubsystemName, sqlConfig.Name))
	if err := ds.Configure(sqlConfig.Data); err != nil {
		return nil, err
	}
	return ds, nil
}
