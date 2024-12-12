package catalog

import (
	"context"
	"fmt"
	"io"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	metricsv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/common/metrics/v1"
	agentstorev1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/agentstore/v1"
	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/hostservice/metricsservice"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/validation"
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

	ValidateOnly bool

	ValidationNotes []string
	ValidationError string
}

func (c *Config) ReportInfo(message string) {
	c.ValidationNotes = append(c.ValidationNotes, message)
}

func (c *Config) ReportInfof(format string, args ...any) {
	c.ReportInfo(fmt.Sprintf(format, args...))
}

func (c *Config) ReportError(message string) {
	if c.ValidationError == "" {
		c.ValidationError = message
	}
	c.ValidationNotes = append(c.ValidationNotes, message)
}

func (c *Config) ReportErrorf(format string, args ...any) {
	c.ReportError(fmt.Sprintf(format, args...))
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

func Load(ctx context.Context, config *Config) (_ *Repository, err error) {
	if c, ok := config.PluginConfigs.Find(nodeAttestorType, jointoken.PluginName); ok && c.IsEnabled() && c.IsExternal() {
		config.ReportError("the built-in join_token node attestor cannot be overridden by an external plugin")
		return nil, fmt.Errorf("the built-in join_token node attestor cannot be overridden by an external plugin")
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
	sqlDataStore, pluginConfigs, err := loadSQLDataStore(ctx, config, coreConfig)
	if err != nil {
		return nil, err
	}
	repo.dsCloser = sqlDataStore

	commonConfig := &catalog.Config{
		Log:           config.Log,
		CoreConfig:    coreConfig,
		PluginConfigs: pluginConfigs,
		HostServices: []pluginsdk.ServiceServer{
			identityproviderv1.IdentityProviderServiceServer(config.IdentityProvider.V1()),
			agentstorev1.AgentStoreServiceServer(config.AgentStore.V1()),
			metricsv1.MetricsServiceServer(metricsservice.V1(config.Metrics)),
		},
		ValidateOnly: config.ValidateOnly,
	}
	repo.catalog, err = catalog.Load(ctx, commonConfig, repo)
	if err != nil {
		return nil, err
	}
	config.ValidationNotes = append(config.ValidationNotes, commonConfig.ValidationNotes...)
	if config.ValidationError == "" {
		config.ValidationError = commonConfig.ValidationError
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

func validateSQLConfig(config *Config) (catalog.PluginConfig, PluginConfigs, validation.ValidationResult) {
	vr := validation.ValidationResult{}
	datastoreConfigs, pluginConfigs := config.PluginConfigs.FilterByType(dataStoreType)

	switch {
	case len(datastoreConfigs) == 0:
		vr.ReportError("expecting a DataStore plugin")
	case len(datastoreConfigs) > 1:
		vr.ReportError("only one DataStore plugin is allowed")
	}

	datastoreConfig := datastoreConfigs[0]

	if datastoreConfig.Name != ds_sql.PluginName {
		vr.ReportErrorf("pluggability for the DataStore is deprecated; only the built-in %q plugin is supported", ds_sql.PluginName)
	}
	if datastoreConfig.IsExternal() {
		vr.ReportErrorf("pluggability for the DataStore is deprecated; only the built-in %q plugin is supported", ds_sql.PluginName)
	}
	if datastoreConfig.DataSource == nil {
		vr.ReportError("internal: DataStore is missing a configuration data source")
	} else if datastoreConfig.DataSource.IsDynamic() {
		vr.ReportInfo("DataStore is not reconfigurable even with a dynamic data source")
	}

	if vr.HasError() {
		return catalog.PluginConfig{}, PluginConfigs(nil), vr
	}
	return datastoreConfig, pluginConfigs, vr
}

func loadSQLDataStore(ctx context.Context, config *Config, coreConfig catalog.CoreConfig) (*ds_sql.Plugin, PluginConfigs, error) {
	dataStoreConfig, pluginConfigs, result := validateSQLConfig(config)
	if result.HasError() {
		return nil, nil, result.Error()
	}
	if dataStoreConfig.DataSource == nil {
		dataStoreConfig.DataSource = catalog.FixedData("")
	}

	dsLog := config.Log.WithField(telemetry.SubsystemName, dataStoreConfig.Name)
	ds := ds_sql.New(dsLog)
	if _, err := catalog.ConfigurePlugin(ctx, coreConfig, ds, dataStoreConfig.DataSource, ""); err != nil {
		return nil, nil, err
	}

	config.Log.WithField(telemetry.Reconfigurable, false).Info("Configured DataStore")
	return ds, pluginConfigs, nil
}

func ValidateConfig(ctx context.Context, config *Config) (*validation.ValidationResult, error) {
	validationResult := &validation.ValidationResult{}
	if c, ok := config.PluginConfigs.Find(nodeAttestorType, jointoken.PluginName); ok && c.IsEnabled() && c.IsExternal() {
		validationResult.ReportError("server catalog: the built-in join_token node attestor cannot be overridden by an external plugin")
		// TODO: filter out plugin and continue
	}

	nullLogger, _ := test.NewNullLogger()
	repo := &Repository{
		log: nullLogger,
	}
	defer func() {
		repo.Close()
	}()

	coreConfig := catalog.CoreConfig{
		TrustDomain: config.TrustDomain,
	}

	dataStoreConfig, _, result := validateSQLConfig(config)
	validationResult.MergeWithFormat("server catalog: %s", result)
	if result.HasError() {
		return validationResult, nil
	}

	ds := ds_sql.New(nullLogger)
	dsConfigString, err := dataStoreConfig.DataSource.Load()
	if err != nil {
		validationResult.ReportError("server catalog: error loading sql datastore plugin config")
	}
	resp, err := ds.Validate(ctx, coreConfig, dsConfigString)
	fmt.Printf("edwin: %+v, config=%s\n", ds, dsConfigString)
	fmt.Printf("edwin: %+v, error=%+v\n", resp, err)

	if err != nil {
		validationResult.ReportError("server catalog: error validating sql datastore plugin config")
	}

	return validationResult, nil
}
