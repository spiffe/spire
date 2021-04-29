package catalog

import (
	"context"
	"io"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/hostservice/metricsservice"
	"github.com/spiffe/spire/pkg/common/telemetry"
	km_telemetry "github.com/spiffe/spire/pkg/common/telemetry/agent/keymanager"
	metricsv0 "github.com/spiffe/spire/proto/spire/hostservice/common/metrics/v0"
)

const (
	keyManagerType       = "KeyManager"
	nodeAttestorType     = "NodeAttestor"
	workloadattestorType = "WorkloadAttestor"
)

type Catalog interface {
	GetKeyManager() keymanager.KeyManager
	GetNodeAttestor() nodeattestor.NodeAttestor
	GetWorkloadAttestors() []workloadattestor.WorkloadAttestor
}

type HCLPluginConfigMap = catalog.HCLPluginConfigMap

type Config struct {
	Log          logrus.FieldLogger
	TrustDomain  spiffeid.TrustDomain
	PluginConfig HCLPluginConfigMap
	Metrics      telemetry.Metrics
}

type Repository struct {
	keyManagerRepository
	nodeAttestorRepository
	workloadAttestorRepository
	io.Closer
}

func (repo *Repository) Plugins() map[string]catalog.PluginRepo {
	return map[string]catalog.PluginRepo{
		keyManagerType:       &repo.keyManagerRepository,
		nodeAttestorType:     &repo.nodeAttestorRepository,
		workloadattestorType: &repo.workloadAttestorRepository,
	}
}

func (repo *Repository) Services() []catalog.ServiceRepo {
	return nil
}

func Load(ctx context.Context, config Config) (_ *Repository, err error) {
	pluginConfigs, err := catalog.PluginConfigsFromHCL(config.PluginConfig)
	if err != nil {
		return nil, err
	}

	// Instantiate and provide host services
	metricsService := metricsservice.New(metricsservice.Config{
		Metrics: config.Metrics,
	})
	hostServices := []catalog.HostServiceServer{
		{
			ServiceServer: metricsv0.MetricsServiceServiceServer(metricsService),
			LegacyType:    "MetricsService",
		},
	}

	// Load the plugins and populate the repository
	repo := new(Repository)
	repo.Closer, err = catalog.Load(ctx, catalog.Config{
		Log: config.Log,
		CoreConfig: catalog.CoreConfig{
			TrustDomain: config.TrustDomain,
		},
		PluginConfigs: pluginConfigs,
		HostServices:  hostServices,
	}, repo)
	if err != nil {
		return nil, err
	}

	// Wrap the facades
	repo.SetKeyManager(km_telemetry.WithMetrics(repo.GetKeyManager(), config.Metrics))

	return repo, nil
}
