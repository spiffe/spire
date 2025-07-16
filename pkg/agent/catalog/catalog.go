package catalog

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	metricsv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/common/metrics/v1"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/jointoken"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/hostservice/metricsservice"
	"github.com/spiffe/spire/pkg/common/telemetry"
	km_telemetry "github.com/spiffe/spire/pkg/common/telemetry/agent/keymanager"
)

const (
	keyManagerType       = "KeyManager"
	nodeAttestorType     = "NodeAttestor"
	svidStoreType        = "SVIDStore"
	workloadattestorType = "WorkloadAttestor"
)

var ReconfigureTask = catalog.ReconfigureTask

type Catalog interface {
	GetKeyManager() keymanager.KeyManager
	GetNodeAttestor() nodeattestor.NodeAttestor
	GetSVIDStoreNamed(name string) (svidstore.SVIDStore, bool)
	GetWorkloadAttestors() []workloadattestor.WorkloadAttestor
}

type PluginConfigs = catalog.PluginConfigs

type PluginConfig = catalog.PluginConfig

type Config struct {
	Log           logrus.FieldLogger
	TrustDomain   spiffeid.TrustDomain
	PluginConfigs PluginConfigs
	Metrics       telemetry.Metrics
}

type Repository struct {
	keyManagerRepository
	nodeAttestorRepository
	svidStoreRepository
	workloadAttestorRepository

	log     logrus.FieldLogger
	catalog *catalog.Catalog
}

func (repo *Repository) Plugins() map[string]catalog.PluginRepo {
	return map[string]catalog.PluginRepo{
		keyManagerType:       &repo.keyManagerRepository,
		nodeAttestorType:     &repo.nodeAttestorRepository,
		svidStoreType:        &repo.svidStoreRepository,
		workloadattestorType: &repo.workloadAttestorRepository,
	}
}

func (repo *Repository) Services() []catalog.ServiceRepo {
	return nil
}

func (repo *Repository) Reconfigure(ctx context.Context) {
	repo.catalog.Reconfigure(ctx)
}

func (repo *Repository) Close() {
	repo.log.Debug("Closing catalog")
	if err := repo.catalog.Close(); err == nil {
		repo.log.Info("Catalog closed")
	} else {
		repo.log.WithError(err).Error("Failed to close catalog")
	}
}

func Load(ctx context.Context, config Config) (_ *Repository, err error) {
	if c, ok := config.PluginConfigs.Find(nodeAttestorType, jointoken.PluginName); ok && c.IsEnabled() && c.IsExternal() {
		return nil, errors.New("the built-in join_token node attestor cannot be overridden by an external plugin")
	}

	// Load the plugins and populate the repository
	repo := &Repository{
		log: config.Log,
	}
	repo.catalog, err = catalog.Load(ctx, catalog.Config{
		Log: config.Log,
		CoreConfig: catalog.CoreConfig{
			TrustDomain: config.TrustDomain,
		},
		PluginConfigs: config.PluginConfigs,
		HostServices: []pluginsdk.ServiceServer{
			metricsv1.MetricsServiceServer(metricsservice.V1(config.Metrics)),
		},
	}, repo)
	if err != nil {
		return nil, err
	}

	// Wrap the facades
	repo.SetKeyManager(km_telemetry.WithMetrics(repo.GetKeyManager(), config.Metrics))

	return repo, nil
}
