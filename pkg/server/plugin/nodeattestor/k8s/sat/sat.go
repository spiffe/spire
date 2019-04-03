package sat

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
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

func BuiltIn() catalog.Plugin {
	return builtIn(New())
}

func builtIn(p *AttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin("k8s_sat",
		nodeattestor.PluginServer(p),
	)
}

type ClusterConfig struct {
	ServiceAccountKeyFile   string   `hcl:"service_account_key_file"`
	ServiceAccountWhitelist []string `hcl:"service_account_whitelist"`
}

type AttestorConfig struct {
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
}

type clusterConfig struct {
	serviceAccountKeys []crypto.PublicKey
	serviceAccounts    map[string]bool
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

	token, err := jwt.ParseSigned(attestationData.Token)
	if err != nil {
		return satError.New("unable to parse token: %v", err)
	}

	claims := new(k8s.SATClaims)
	err = k8s.VerifyTokenSignature(cluster.serviceAccountKeys, token, claims)
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
			k8s.MakeSelector(pluginName, "cluster", attestationData.Cluster),
			k8s.MakeSelector(pluginName, "agent_ns", claims.Namespace),
			k8s.MakeSelector(pluginName, "agent_sa", claims.ServiceAccountName),
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
		if cluster.ServiceAccountKeyFile == "" {
			return nil, satError.New("cluster %q configuration missing service account key file", name)
		}
		if len(cluster.ServiceAccountWhitelist) == 0 {
			return nil, satError.New("cluster %q configuration must have at least one service account whitelisted", name)
		}

		serviceAccountKeys, err := k8s.LoadServiceAccountKeys(cluster.ServiceAccountKeyFile)
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
