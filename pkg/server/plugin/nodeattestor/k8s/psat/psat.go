package psat

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/client"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	pluginName = "k8s_psat"
)

var (
	defaultAudience                     = []string{"spire-server"}
	psatError                           = errs.Class("k8s-psat")
	_               nodeattestor.Plugin = (*AttestorPlugin)(nil)
)

// NewAttestorPlugin creates a new PSAT node attestor plugin
func NewAttestorPlugin() *AttestorPlugin {
	return &AttestorPlugin{}
}

//AttestorPlugin is a PSAT (Projected SAT) node attestor plugin
type AttestorPlugin struct {
	mu     sync.RWMutex
	config *attestorConfig
}

// ClusterConfig holds a single cluster configuration
type ClusterConfig struct {
	// API server public key file path.
	// Public key is used for token validation
	APIServerKeyFile string `hcl:"service_account_key_file"`

	// Array of whitelisted service accounts names
	// Attestation is denied if comming from a service account that is not in the list
	ServiceAccountWhitelist []string `hcl:"service_account_whitelist"`

	// Audience for PSAT token validation
	// If audience is not configured, defaultAudience will be used
	// If audience value is set to an empty slice, validation is skipped
	Audience *[]string `hcl:"audience"`

	// If true, the plugin queries k8s API Server for extra selectors
	QueryAPIServer bool `hcl:"enable_api_server_queries"`

	// Kubernetes configuration file path (only used if QueryAPIServer is enabled)
	// Used to create a k8s client to query the API server.
	KubeConfigFile string `hcl:"kube_config_file"`
}

// AttestorConfig contains a map of clusters that uses cluster name as key
type AttestorConfig struct {
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
}

type clusterConfig struct {
	keys            []crypto.PublicKey
	serviceAccounts map[string]bool
	audience        []string
	queryAPIServer  bool
	k8sClient       client.K8SClient
}

type attestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig
}

func (p *AttestorPlugin) Attest(stream nodeattestor.Attest_PluginStream) error {
	req, err := stream.Recv()
	if err != nil {
		return psatError.Wrap(err)
	}

	config, err := p.getConfig()
	if err != nil {
		return psatError.Wrap(err)
	}

	if req.AttestedBefore {
		return psatError.New("node has already attested")
	}

	if req.AttestationData == nil {
		return psatError.New("missing attestation data")
	}

	if dataType := req.AttestationData.Type; dataType != pluginName {
		return psatError.New("unexpected attestation data type %q", dataType)
	}

	if req.AttestationData.Data == nil {
		return psatError.New("missing attestation data payload")
	}

	attestationData := new(k8s.PSATAttestationData)
	if err := json.Unmarshal(req.AttestationData.Data, attestationData); err != nil {
		return psatError.New("failed to unmarshal data payload: %v", err)
	}

	if attestationData.Cluster == "" {
		return psatError.New("missing cluster in attestation data")
	}

	if attestationData.Token == "" {
		return psatError.New("missing token in attestation data")
	}

	cluster := config.clusters[attestationData.Cluster]
	if cluster == nil {
		return psatError.New("not configured for cluster %q", attestationData.Cluster)
	}

	token, err := jwt.ParseSigned(attestationData.Token)
	if err != nil {
		return psatError.New("unable to parse token: %v", err)
	}

	claims := new(k8s.PSATClaims)
	err = k8s.VerifyTokenSignature(cluster.keys, token, claims)
	if err != nil {
		return psatError.Wrap(err)
	}

	if err := claims.Validate(jwt.Expected{
		Issuer:   "api",
		Time:     time.Now(),
		Audience: cluster.audience,
	}); err != nil {
		return psatError.New("unable to validate token claims: %v", err)
	}

	if claims.K8s.Namespace == "" {
		return psatError.New("token missing namespace claim")
	}

	if claims.K8s.ServiceAccount.Name == "" {
		return psatError.New("token missing service account name claim")
	}

	if claims.K8s.Pod.Name == "" {
		return psatError.New("token missing pod name claim")
	}

	if claims.K8s.Pod.UID == "" {
		return psatError.New("token missing pod UID claim")
	}

	serviceAccountName := fmt.Sprintf("%s:%s", claims.K8s.Namespace, claims.K8s.ServiceAccount.Name)
	if !cluster.serviceAccounts[serviceAccountName] {
		return psatError.New("%q is not a whitelisted service account", serviceAccountName)
	}

	selectors, err := makeSelectors(claims, attestationData.Cluster, cluster)
	if err != nil {
		return err
	}

	return stream.Send(&nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: k8s.AgentID(pluginName, config.trustDomain, attestationData.Cluster, claims.K8s.Pod.UID),
		Selectors:    selectors,
	})
}

func (p *AttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	hclConfig := new(AttestorConfig)
	if err := hcl.Decode(hclConfig, req.Configuration); err != nil {
		return nil, psatError.New("unable to decode configuration: %v", err)
	}
	if req.GlobalConfig == nil {
		return nil, psatError.New("global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, psatError.New("global configuration missing trust domain")
	}

	if len(hclConfig.Clusters) == 0 {
		return nil, psatError.New("configuration must have at least one cluster")
	}

	config := &attestorConfig{
		trustDomain: req.GlobalConfig.TrustDomain,
		clusters:    make(map[string]*clusterConfig),
	}

	for name, cluster := range hclConfig.Clusters {
		if cluster.APIServerKeyFile == "" {
			return nil, psatError.New("cluster %q configuration missing service account keys file", name)
		}
		if len(cluster.ServiceAccountWhitelist) == 0 {
			return nil, psatError.New("cluster %q configuration must have at least one service account whitelisted", name)
		}

		keys, err := k8s.LoadServiceAccountKeys(cluster.APIServerKeyFile)
		if err != nil {
			return nil, psatError.New("failed to load cluster %q service account keys from %q: %v", name, cluster.APIServerKeyFile, err)
		}
		if len(keys) == 0 {
			return nil, psatError.New("cluster %q has no service account keys in %q", name, cluster.APIServerKeyFile)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range cluster.ServiceAccountWhitelist {
			serviceAccounts[serviceAccount] = true
		}

		var audience []string
		if cluster.Audience == nil {
			audience = defaultAudience
		}

		var k8sClient client.K8SClient
		if cluster.QueryAPIServer {
			k8sClient = client.NewK8SClient(cluster.KubeConfigFile)
		}

		config.clusters[name] = &clusterConfig{
			keys:            keys,
			serviceAccounts: serviceAccounts,
			audience:        audience,
			queryAPIServer:  cluster.QueryAPIServer,
			k8sClient:       k8sClient,
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
		return nil, psatError.New("not configured")
	}
	return p.config, nil
}

func (p *AttestorPlugin) setConfig(config *attestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func makeSelectors(claims *k8s.PSATClaims, clusterName string, cluster *clusterConfig) ([]*common.Selector, error) {
	// Common selectors
	selectors := []*common.Selector{
		k8s.MakeSelector(pluginName, "cluster", clusterName),
		k8s.MakeSelector(pluginName, "agent_ns", claims.K8s.Namespace),
		k8s.MakeSelector(pluginName, "agent_sa", claims.K8s.ServiceAccount.Name),
		k8s.MakeSelector(pluginName, "agent_pod_name", claims.K8s.Pod.Name),
		k8s.MakeSelector(pluginName, "agent_pod_uid", claims.K8s.Pod.UID),
	}

	// Additional selectors (only if query k8s api server is enabled)
	if cluster.queryAPIServer {
		node, err := cluster.k8sClient.GetNode(claims.K8s.Namespace, claims.K8s.Pod.Name)
		if err != nil {
			return nil, psatError.New("can't get node name from k8s api: %v", err)
		}
		selectors = append(selectors, k8s.MakeSelector(pluginName, "agent_node_name", node))
	}

	return selectors, nil
}
