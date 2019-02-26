package sat

import (
	"context"
	"crypto"
	"fmt"
	"sync"

	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	sat_common "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8s/common"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	pluginName = "k8s_sat"
)

var (
	satError = errs.Class("k8s-sat")
)

type ClusterConfig struct {
	ServiceAccountKeyFile   string   `hcl:"service_account_key_file"`
	ServiceAccountWhitelist []string `hcl:"service_account_whitelist"`
}

type SATAttestorConfig struct {
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
}

type clusterConfig struct {
	serviceAccountKeys []crypto.PublicKey
	serviceAccounts    map[string]bool
}

type satAttestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig
}

type SATAttestorPlugin struct {
	*sat_common.CommonAttestorPlugin
	mu     sync.RWMutex
	config *satAttestorConfig
}

var _ nodeattestor.Plugin = (*SATAttestorPlugin)(nil)

func NewSATAttestorPlugin() *SATAttestorPlugin {
	return &SATAttestorPlugin{
		CommonAttestorPlugin: sat_common.NewCommonAttestorPlugin(pluginName),
	}
}

func (p *SATAttestorPlugin) Attest(stream nodeattestor.Attest_PluginStream) error {
	req, err := stream.Recv()
	if err != nil {
		return satError.Wrap(err)
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	attestationData, err := p.ValidateAttestReq(req)
	if err != nil {
		return satError.Wrap(err)
	}

	cluster := config.clusters[attestationData.Cluster]
	if cluster == nil {
		return satError.New("not configured for cluster %q", attestationData.Cluster)
	}

	token, err := jwt.ParseSigned(attestationData.Token)
	if err != nil {
		return satError.New("unable to parse token: %v", err)
	}

	claims := new(k8s.SATClaims)
	err = p.VerifyTokenSignature(cluster.serviceAccountKeys, token, claims)
	if err != nil {
		return satError.Wrap(err)
	}

	// TODO: service account tokens don't currently expire.... when they do, validate the time (with leeway)
	if err := claims.Validate(jwt.Expected{
		Issuer: "kubernetes/serviceaccount",
	}); err != nil {
		return satError.New("unable to validate token claims: %v", err)
	}

	if claims.Namespace == "" {
		return satError.New("token missing namespace claim")
	}

	if claims.ServiceAccountName == "" {
		return satError.New("token missing service account name claim")
	}

	serviceAccountName := fmt.Sprintf("%s:%s", claims.Namespace, claims.ServiceAccountName)

	if !cluster.serviceAccounts[serviceAccountName] {
		return satError.New("%q is not a whitelisted service account", serviceAccountName)
	}

	return stream.Send(&nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: k8s.AgentID(pluginName, config.trustDomain, attestationData.Cluster, attestationData.UUID),
		Selectors: []*common.Selector{
			p.MakeSelector("cluster", attestationData.Cluster),
			p.MakeSelector("agent_ns", claims.Namespace),
			p.MakeSelector("agent_sa", claims.ServiceAccountName),
		},
	})
}

func (p *SATAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	hclConfig := new(SATAttestorConfig)
	err := p.ValidateConfigReq(hclConfig, req)
	if err != nil {
		return nil, satError.Wrap(err)
	}

	if len(hclConfig.Clusters) == 0 {
		return nil, satError.New("configuration must have at least one cluster")
	}

	config := &satAttestorConfig{
		trustDomain: req.GlobalConfig.TrustDomain,
		clusters:    make(map[string]*clusterConfig),
	}
	config.trustDomain = req.GlobalConfig.TrustDomain
	for name, cluster := range hclConfig.Clusters {
		if cluster.ServiceAccountKeyFile == "" {
			return nil, satError.New("cluster %q configuration missing service account key file", name)
		}
		if len(cluster.ServiceAccountWhitelist) == 0 {
			return nil, satError.New("cluster %q configuration must have at least one service account whitelisted", name)
		}

		serviceAccountKeys, err := p.LoadServiceAccountKeys(cluster.ServiceAccountKeyFile)
		if err != nil {
			return nil, satError.New("failed to load cluster %q service account keys from %q: %v", name, cluster.ServiceAccountKeyFile, err)
		}

		if len(serviceAccountKeys) == 0 {
			return nil, satError.New("cluster %q has no service account keys in %q", name, cluster.ServiceAccountKeyFile)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range cluster.ServiceAccountWhitelist {
			serviceAccounts[serviceAccount] = true
		}

		config.clusters[name] = &clusterConfig{
			serviceAccountKeys: serviceAccountKeys,
			serviceAccounts:    serviceAccounts,
		}
	}

	p.setConfig(config)
	return &spi.ConfigureResponse{}, nil
}

func (p *SATAttestorPlugin) getConfig() (*satAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, satError.New("not configured")
	}
	return p.config, nil
}

func (p *SATAttestorPlugin) setConfig(config *satAttestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}
