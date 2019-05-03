package sat

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/apiserver"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
	"github.com/zeebo/errs"
)

const (
	pluginName = "k8s_sat"
)

var (
	satError = errs.Class("k8s-sat")
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *AttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin("k8s_sat",
		nodeattestor.PluginServer(p),
	)
}

type ClusterConfig struct {
	ServiceAccountWhitelist []string `hcl:"service_account_whitelist"`

	// Kubernetes configuration file path
	// Used to create a client to query the Kubernetes API server. If empty string, 'InClusterConfig' is used
	KubeConfigFile string `hcl:"kube_config_file"`
}

type AttestorConfig struct {
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
}

type clusterConfig struct {
	serviceAccounts map[string]bool
	client          apiserver.Client
}

type attestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig
}

type AttestorPlugin struct {
	mu     sync.RWMutex
	config *attestorConfig
}

var _ nodeattestor.NodeAttestorServer = (*AttestorPlugin)(nil)

func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

func (p *AttestorPlugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return satError.Wrap(err)
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	if req.AttestedBefore {
		return satError.New("node has already attested")
	}

	if req.AttestationData == nil {
		return satError.New("missing attestation data")
	}

	if dataType := req.AttestationData.Type; dataType != pluginName {
		return satError.New("unexpected attestation data type %q", dataType)
	}

	if req.AttestationData.Data == nil {
		return satError.New("missing attestation data payload")
	}

	attestationData := new(k8s.SATAttestationData)
	if err := json.Unmarshal(req.AttestationData.Data, attestationData); err != nil {
		return satError.New("failed to unmarshal data payload: %v", err)
	}

	if attestationData.Cluster == "" {
		return satError.New("missing cluster in attestation data")
	}

	if attestationData.UUID == "" {
		return satError.New("missing UUID in attestation data")
	}

	if attestationData.Token == "" {
		return satError.New("missing token in attestation data")
	}

	cluster := config.clusters[attestationData.Cluster]
	if cluster == nil {
		return satError.New("not configured for cluster %q", attestationData.Cluster)
	}

	// Empty audience is used since SAT does not support audiences
	tokenStatus, err := cluster.client.ValidateToken(attestationData.Token, []string{})
	if err != nil {
		return satError.New("unable to validate token with TokenReview API: %v", err)
	}

	if !tokenStatus.Authenticated {
		return satError.New("token not authenticated according to TokenReview API")
	}

	namespace, serviceAccountName, err := k8s.GetNamesFromTokenStatus(tokenStatus)
	if err != nil {
		return satError.New("fail to parse username from token review status: %v", err)
	}
	fullServiceAccountName := fmt.Sprintf("%v:%v", namespace, serviceAccountName)

	if !cluster.serviceAccounts[fullServiceAccountName] {
		return satError.New("%q is not a whitelisted service account", fullServiceAccountName)
	}

	return stream.Send(&nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: k8s.AgentID(pluginName, config.trustDomain, attestationData.Cluster, attestationData.UUID),
		Selectors: []*common.Selector{
			k8s.MakeSelector(pluginName, "cluster", attestationData.Cluster),
			k8s.MakeSelector(pluginName, "agent_ns", namespace),
			k8s.MakeSelector(pluginName, "agent_sa", serviceAccountName),
		},
	})
}

func (p *AttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	hclConfig := new(AttestorConfig)
	if err := hcl.Decode(hclConfig, req.Configuration); err != nil {
		return nil, satError.New("unable to decode configuration: %v", err)
	}
	if req.GlobalConfig == nil {
		return nil, satError.New("global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, satError.New("global configuration missing trust domain")
	}

	if len(hclConfig.Clusters) == 0 {
		return nil, satError.New("configuration must have at least one cluster")
	}

	config := &attestorConfig{
		trustDomain: req.GlobalConfig.TrustDomain,
		clusters:    make(map[string]*clusterConfig),
	}
	config.trustDomain = req.GlobalConfig.TrustDomain
	for name, cluster := range hclConfig.Clusters {
		if len(cluster.ServiceAccountWhitelist) == 0 {
			return nil, satError.New("cluster %q configuration must have at least one service account whitelisted", name)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range cluster.ServiceAccountWhitelist {
			serviceAccounts[serviceAccount] = true
		}

		config.clusters[name] = &clusterConfig{
			serviceAccounts: serviceAccounts,
			client:          apiserver.New(cluster.KubeConfigFile),
		}
	}

	p.setConfig(config)
	return &spi.ConfigureResponse{}, nil
}

func (p *AttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *AttestorPlugin) getConfig() (*attestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, satError.New("not configured")
	}
	return p.config, nil
}

func (p *AttestorPlugin) setConfig(config *attestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}
