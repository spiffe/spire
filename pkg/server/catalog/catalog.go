package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	metricsv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/common/metrics/v1"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/hostservice/metricsservice"
	"github.com/spiffe/spire/pkg/common/telemetry"
	ds_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server/datastore"
	km_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server/keymanager"
	"github.com/spiffe/spire/pkg/server/cache/dscache"
	"github.com/spiffe/spire/pkg/server/datastore"
	ds_sql "github.com/spiffe/spire/pkg/server/datastore/sqlstore"
	"github.com/spiffe/spire/pkg/server/hostservice/agentstore"
	"github.com/spiffe/spire/pkg/server/hostservice/identityprovider"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/jointoken"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
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

type HCLPluginConfig = catalog.HCLPluginConfig

type Config struct {
	Log          logrus.FieldLogger
	TrustDomain  spiffeid.TrustDomain
	PluginConfig HCLPluginConfigMap

	Metrics          telemetry.Metrics
	IdentityProvider *identityprovider.IdentityProvider
	AgentStore       *agentstore.AgentStore
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

	log             logrus.FieldLogger
	dataStoreCloser io.Closer
	catalogCloser   io.Closer
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

func (repo *Repository) Close() {
	// Must close in reverse initialization order!

	if repo.catalogCloser != nil {
		repo.log.Debug("Closing catalog")
		if err := repo.catalogCloser.Close(); err == nil {
			repo.log.Info("Catalog closed")
		} else {
			repo.log.WithError(err).Error("Failed to close catalog")
		}
	}

	if repo.dataStoreCloser != nil {
		repo.log.Debug("Closing DataStore")
		if err := repo.dataStoreCloser.Close(); err == nil {
			repo.log.Info("DataStore closed")
		} else {
			repo.log.WithError(err).Error("Failed to close DataStore")
		}
	}
}

func Load(ctx context.Context, config Config) (_ *Repository, err error) {
	// DEPRECATE: make this an error in SPIRE 1.5
	if len(config.PluginConfig[nodeResolverType]) > 0 {
		config.Log.Warn("The node resolver plugin type is deprecated and will be removed from a future release")
	}

	// DEPRECATE: make this an error in SPIRE 1.5
	if c, ok := config.PluginConfig[nodeAttestorType][jointoken.PluginName]; ok && c.IsEnabled() && c.IsExternal() {
		config.Log.Warn("The built-in join_token node attestor cannot be overridden by an external plugin. The external plugin will be ignored; this will be a configuration error in a future release.")
		config.PluginConfig[nodeAttestorType][jointoken.PluginName] = catalog.HCLPluginConfig{}
	}

	repo := &Repository{
		log: config.Log,
	}
	defer func() {
		if err != nil {
			repo.Close()
		}
	}()

	// Strip out the Datastore plugin configuration and load the SQL plugin
	// directly. This allows us to bypass gRPC and get rid of response limits.
	dataStoreConfig := config.PluginConfig[dataStoreType]
	delete(config.PluginConfig, dataStoreType)
	sqlDataStore, err := loadSQLDataStore(ctx, config.Log, dataStoreConfig)
	if err != nil {
		return nil, err
	}
	repo.dataStoreCloser = sqlDataStore

	pluginConfigs, err := catalog.PluginConfigsFromHCL(config.PluginConfig)
	if err != nil {
		return nil, err
	}

	repo.catalogCloser, err = catalog.Load(ctx, catalog.Config{
		Log: config.Log,
		CoreConfig: catalog.CoreConfig{
			TrustDomain: config.TrustDomain,
		},
		PluginConfigs: pluginConfigs,
		HostServices: []pluginsdk.ServiceServer{
			identityproviderv1.IdentityProviderServiceServer(config.IdentityProvider.V1()),
			agentstorev1.AgentStoreServiceServer(config.AgentStore.V1()),
			metricsv1.MetricsServiceServer(metricsservice.V1(config.Metrics)),
		},
	}, repo)
	if err != nil {
		return nil, err
	}

	var dataStore datastore.DataStore = sqlDataStore
	_ = config.HealthChecker.AddCheck("catalog.datastore", &datastore.Health{
		DataStore: dataStore,
	})

	dataStore = ds_telemetry.WithMetrics(dataStore, config.Metrics)
	dataStore = dscache.New(dataStore, clock.New())

	repo.SetDataStore(dataStore)
	repo.SetKeyManager(km_telemetry.WithMetrics(repo.GetKeyManager(), config.Metrics))

	return repo, nil
}

func loadSQLDataStore(ctx context.Context, log logrus.FieldLogger, datastoreConfig map[string]catalog.HCLPluginConfig) (*ds_sql.Plugin, error) {
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
	if err := ds.Configure(ctx, sqlConfig.Data); err != nil {
		return nil, err
	}
	return ds, nil
}
