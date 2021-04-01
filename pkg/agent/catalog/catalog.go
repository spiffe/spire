package catalog

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	km_disk "github.com/spiffe/spire/pkg/agent/plugin/keymanager/disk"
	km_memory "github.com/spiffe/spire/pkg/agent/plugin/keymanager/memory"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	na_aws_iid "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/aws"
	na_azure_msi "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/azure"
	na_devid "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/devid"
	na_gcp_iit "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/gcp"
	na_join_token "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/jointoken"
	na_k8s_psat "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/k8s/psat"
	na_k8s_sat "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/k8s/sat"
	na_sshpop "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/sshpop"
	na_x509pop "github.com/spiffe/spire/pkg/agent/plugin/nodeattestor/x509pop"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	wa_docker "github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker"
	wa_k8s "github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/k8s"
	wa_unix "github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/unix"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/telemetry"
	keymanager_telemetry "github.com/spiffe/spire/pkg/common/telemetry/agent/keymanager"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/plugin/agent/keymanager/v0"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/plugin/agent/nodeattestor/v0"
	workloadattestorv0 "github.com/spiffe/spire/proto/spire/plugin/agent/workloadattestor/v0"
)

type Catalog interface {
	GetKeyManager() keymanager.KeyManager
	GetNodeAttestor() nodeattestor.NodeAttestor
	GetWorkloadAttestors() []workloadattestor.WorkloadAttestor
}

type GlobalConfig = catalog.GlobalConfig
type HCLPluginConfig = catalog.HCLPluginConfig
type HCLPluginConfigMap = catalog.HCLPluginConfigMap

func KnownPlugins() []catalog.PluginClient {
	return []catalog.PluginClient{
		keymanagerv0.PluginClient,
		nodeattestorv0.PluginClient,
		workloadattestorv0.PluginClient,
	}
}

func KnownServices() []catalog.ServiceClient {
	return []catalog.ServiceClient{}
}

func BuiltIns() []catalog.Plugin {
	return []catalog.Plugin{
		km_disk.BuiltIn(),
		km_memory.BuiltIn(),
		na_aws_iid.BuiltIn(),
		na_join_token.BuiltIn(),
		na_gcp_iit.BuiltIn(),
		na_x509pop.BuiltIn(),
		na_sshpop.BuiltIn(),
		na_azure_msi.BuiltIn(),
		na_k8s_sat.BuiltIn(),
		na_k8s_psat.BuiltIn(),
		na_devid.BuiltIn(),
		wa_k8s.BuiltIn(),
		wa_unix.BuiltIn(),
		wa_docker.BuiltIn(),
	}
}

type WorkloadAttestor struct {
	catalog.PluginInfo
	workloadattestor.WorkloadAttestor
}

type Plugins struct {
	KeyManager        keymanager.KeyManager
	NodeAttestor      nodeattestor.NodeAttestor
	WorkloadAttestors []workloadattestor.WorkloadAttestor
}

var _ Catalog = (*Plugins)(nil)

func (p *Plugins) GetKeyManager() keymanager.KeyManager {
	return p.KeyManager
}

func (p *Plugins) GetNodeAttestor() nodeattestor.NodeAttestor {
	return p.NodeAttestor
}

func (p *Plugins) GetWorkloadAttestors() []workloadattestor.WorkloadAttestor {
	return p.WorkloadAttestors
}

type Config struct {
	Log          logrus.FieldLogger
	GlobalConfig *GlobalConfig
	PluginConfig HCLPluginConfigMap
	HostServices []catalog.HostServiceServer
	Metrics      *telemetry.MetricsImpl
}

type Repository struct {
	Catalog
	catalog.Closer
}

func Load(ctx context.Context, config Config) (*Repository, error) {
	pluginConfig, err := catalog.PluginConfigsFromHCL(config.PluginConfig)
	if err != nil {
		return nil, err
	}

	p := new(versionedPlugins)
	closer, err := catalog.Fill(ctx, catalog.Config{
		Log:           config.Log,
		GlobalConfig:  config.GlobalConfig,
		PluginConfig:  pluginConfig,
		KnownPlugins:  KnownPlugins(),
		KnownServices: KnownServices(),
		BuiltIns:      BuiltIns(),
		HostServices:  config.HostServices,
	}, p)
	if err != nil {
		return nil, err
	}

	p.KeyManager.Plugin = keymanager_telemetry.WithMetrics(p.KeyManager.Plugin, config.Metrics)

	var workloadAttestors []workloadattestor.WorkloadAttestor
	for _, workloadAttestorV0 := range p.WorkloadAttestors {
		workloadAttestors = append(workloadAttestors, workloadAttestorV0)
	}

	return &Repository{
		Catalog: &Plugins{
			KeyManager:        p.KeyManager,
			NodeAttestor:      p.NodeAttestor,
			WorkloadAttestors: workloadAttestors,
		},
		Closer: closer,
	}, nil
}

// versionedPlugins is a temporary struct with the v0 version shims as they are
// introduced. The catalog will fill this struct, which is then converted to
// the Plugins struct which contains the facade interfaces. It will be removed
// when the catalog is refactored to leverage the new common catalog with
// native versioning support (see issue #2153).
type versionedPlugins struct {
	KeyManager        keymanager.V0
	NodeAttestor      nodeattestor.V0
	WorkloadAttestors []workloadattestor.V0 `catalog:"min=1"`
}
