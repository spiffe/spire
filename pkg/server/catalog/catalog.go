package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	metricsv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/common/metrics/v1"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
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
	"github.com/spiffe/spire/pkg/server/plugin/bundlepublisher"
	"github.com/spiffe/spire/pkg/server/plugin/credentialcomposer"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor/jointoken"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
)

const (
	bundlePublisherType    = "BundlePublisher"
	credentialComposerType = "CredentialComposer" //nolint: gosec // this is not a hardcoded credential...
	dataStoreType          = "DataStore"
	keyManagerType         = "KeyManager"
	nodeAttestorType       = "NodeAttestor"
	notifierType           = "Notifier"
	upstreamAuthorityType  = "UpstreamAuthority"
)

var ReconfigureTask = catalog.ReconfigureTask

type Catalog interface {
	GetBundlePublishers() []bundlepublisher.BundlePublisher
	GetCredentialComposers() []credentialcomposer.CredentialComposer
	GetDataStore() datastore.DataStore
	GetNodeAttestorNamed(name string) (nodeattestor.NodeAttestor, bool)
	GetKeyManager() keymanager.KeyManager
	GetNotifiers() []notifier.Notifier
	GetUpstreamAuthority() (upstreamauthority.UpstreamAuthority, bool)
}

type PluginConfigs = catalog.PluginConfigs

type Config struct {
	Log           logrus.FieldLogger
	TrustDomain   spiffeid.TrustDomain
	PluginConfigs PluginConfigs

	Metrics          telemetry.Metrics
	IdentityProvider *identityprovider.IdentityProvider
	AgentStore       *agentstore.AgentStore
	HealthChecker    health.Checker
}

type datastoreRepository struct{ datastore.Repository }

type Repository struct {
	bundlePublisherRepository
	credentialComposerRepository
	datastoreRepository
	keyManagerRepository
	nodeAttestorRepository
	notifierRepository
	upstreamAuthorityRepository

	log      logrus.FieldLogger
	dsCloser io.Closer
	catalog  *catalog.Catalog
}

type dsConfigurer struct {
	ds *ds_sql.Plugin
}

func (c *dsConfigurer) Configure(ctx context.Context, _ catalog.CoreConfig, configuration string) error {
	return c.ds.Configure(ctx, configuration)
}

func (c *dsConfigurer) Validate(ctx context.Context, coreConfig catalog.CoreConfig, configuration string) (*configv1.ValidateResponse, error) {
	return c.ds.Validate(ctx, coreConfig, configuration)
}

func (repo *Repository) Plugins() map[string]catalog.PluginRepo {
	return map[string]catalog.PluginRepo{
		bundlePublisherType:    &repo.bundlePublisherRepository,
		credentialComposerType: &repo.credentialComposerRepository,
		keyManagerType:         &repo.keyManagerRepository,
		nodeAttestorType:       &repo.nodeAttestorRepository,
		notifierType:           &repo.notifierRepository,
		upstreamAuthorityType:  &repo.upstreamAuthorityRepository,
	}
}

func (repo *Repository) Services() []catalog.ServiceRepo {
	return nil
}

func (repo *Repository) Reconfigure(ctx context.Context) {
	repo.catalog.Reconfigure(ctx)
}

func (repo *Repository) Close() {
	// Must close in reverse initialization order!

	if repo.catalog != nil {
		repo.log.Debug("Closing catalog")
		if err := repo.catalog.Close(); err == nil {
			repo.log.Info("Catalog closed")
		} else {
			repo.log.WithError(err).Error("Failed to close catalog")
		}
	}

	if repo.dsCloser != nil {
		repo.log.Debug("Closing DataStore")
		if err := repo.dsCloser.Close(); err == nil {
			repo.log.Info("DataStore closed")
		} else {
			repo.log.WithError(err).Error("Failed to close DataStore")
		}
	}
}

func Load(ctx context.Context, config Config) (_ *Repository, err error) {
	if c, ok := config.PluginConfigs.Find(nodeAttestorType, jointoken.PluginName); ok && c.IsEnabled() && c.IsExternal() {
		return nil, errors.New("the built-in join_token node attestor cannot be overridden by an external plugin")
	}

	repo := &Repository{
		log: config.Log,
	}
	defer func() {
		if err != nil {
			repo.Close()
		}
	}()

	coreConfig := catalog.CoreConfig{
		TrustDomain: config.TrustDomain,
	}

	// Strip out the Datastore plugin configuration and load the SQL plugin
	// directly. This allows us to bypass gRPC and get rid of response limits.
	dataStoreConfigs, pluginConfigs := config.PluginConfigs.FilterByType(dataStoreType)
	sqlDataStore, err := loadSQLDataStore(ctx, config, coreConfig, dataStoreConfigs)
	if err != nil {
		return nil, err
	}
	repo.dsCloser = sqlDataStore

	repo.catalog, err = catalog.Load(ctx, catalog.Config{
		Log:           config.Log,
		CoreConfig:    coreConfig,
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

func ValidateConfig(ctx context.Context, config Config) (pluginNotes map[string][]string, err error) {
	if c, ok := config.PluginConfigs.Find(nodeAttestorType, jointoken.PluginName); ok && c.IsEnabled() && c.IsExternal() {
		return nil, errors.New("the built-in join_token node attestor cannot be overridden by an external plugin")
	}

	repo := &Repository{
		log: config.Log,
	}
	defer func() {
		repo.Close()
	}()

	coreConfig := catalog.CoreConfig{
		TrustDomain: config.TrustDomain,
	}

	pluginNotes = make(map[string][]string)
	dataStoreConfigs, pluginConfigs := config.PluginConfigs.FilterByType(dataStoreType)
	datastorePluginId := fmt.Sprintf("%s \"%s\"", dataStoreType, "sql")
	if len(dataStoreConfigs) == 0 {
		pluginNotes[datastorePluginId] = append(pluginNotes[datastorePluginId], "'datastore' must be configured")
	} else {
		dsConfigString, err := catalog.GetPluginConfigString(dataStoreConfigs[0])
		if err != nil {
			return nil, fmt.Errorf("failed to get DataStore configuration: %w", err)
		}

		ds := ds_sql.New(config.Log)
		resp, err := ds.Validate(ctx, coreConfig, dsConfigString)
		if err != nil {
			pluginNotes[datastorePluginId] = append(pluginNotes[datastorePluginId], err.Error())
		}
		if resp != nil && len(resp.Notes) != 0 {
			pluginNotes[datastorePluginId] = append(pluginNotes[datastorePluginId], resp.Notes...)
		}

		repo.dsCloser = ds
	}

	validateResp, err := catalog.ValidatePluginConfigs(ctx, catalog.Config{
		Log:           config.Log,
		CoreConfig:    coreConfig,
		PluginConfigs: pluginConfigs,
		HostServices: []pluginsdk.ServiceServer{
			identityproviderv1.IdentityProviderServiceServer(config.IdentityProvider.V1()),
			agentstorev1.AgentStoreServiceServer(config.AgentStore.V1()),
			metricsv1.MetricsServiceServer(metricsservice.V1(config.Metrics)),
		},
	}, repo)

	if validateResp != nil {
		maps.Copy(pluginNotes, validateResp)
	}

	return pluginNotes, err
}

func loadSQLDataStore(ctx context.Context, config Config, coreConfig catalog.CoreConfig, datastoreConfigs catalog.PluginConfigs) (*ds_sql.Plugin, error) {
	switch {
	case len(datastoreConfigs) == 0:
		return nil, errors.New("expecting a DataStore plugin")
	case len(datastoreConfigs) > 1:
		return nil, errors.New("only one DataStore plugin is allowed")
	}

	sqlConfig := datastoreConfigs[0]

	if sqlConfig.Name != ds_sql.PluginName {
		return nil, fmt.Errorf("pluggability for the DataStore is deprecated; only the built-in %q plugin is supported", ds_sql.PluginName)
	}
	if sqlConfig.IsExternal() {
		return nil, fmt.Errorf("pluggability for the DataStore is deprecated; only the built-in %q plugin is supported", ds_sql.PluginName)
	}
	if sqlConfig.DataSource == nil {
		sqlConfig.DataSource = catalog.FixedData("")
	}

	dsLog := config.Log.WithField(telemetry.SubsystemName, sqlConfig.Name)
	ds := ds_sql.New(dsLog)
	dsConf := &dsConfigurer{ds: ds}
	if _, err := catalog.ConfigurePlugin(ctx, coreConfig, dsConf, sqlConfig.DataSource, ""); err != nil {
		return nil, err
	}

	if sqlConfig.DataSource.IsDynamic() {
		config.Log.Warn("DataStore is not reconfigurable even with a dynamic data source")
	}

	config.Log.WithField(telemetry.Reconfigurable, false).Info("Configured DataStore")
	return ds, nil
}
