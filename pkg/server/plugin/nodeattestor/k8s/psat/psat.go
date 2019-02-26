package psat

import (
	"context"
	"crypto"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/client"
	sat_common "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/k8s/common"
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
	psatError                     = errs.Class("k8s-psat")
	_         nodeattestor.Plugin = (*PSATAttestorPlugin)(nil)
)

//PSATAttestorPlugin holds PSAT (Projected SAT) node attestor logic
// SAT common functionality is encapsuled in CommonAttestorPlugin
type PSATAttestorPlugin struct {
	*sat_common.CommonAttestorPlugin
	mu     sync.RWMutex
	config *psatAttestorConfig
}

// NewPSATAttestorPlugin creates a new PSAT node attestor
func NewPSATAttestorPlugin() *PSATAttestorPlugin {
	return &PSATAttestorPlugin{
		CommonAttestorPlugin: sat_common.NewCommonAttestorPlugin(pluginName),
	}
}

// ClusterConfig holds a single cluster configuration
type ClusterConfig struct {
	// Kubernetes configuration file path
	// This file is used to create a k8s client to query the API server.
	KubeConfigFile string `hcl:"kube_config_file"`

	// API server public key file path.
	// Public key is used for token validation
	APIServerKeyFile string `hcl:"api_server_key_file"`

	// Array of withelisted service accounts names
	// Attestation is denied if comming from a service account that is not in the list
	ServiceAccountWhitelist []string `hcl:"service_account_whitelist"`

	// Array of withelisted pod names prefixes
	// Attestation is denied if comming from a pod which prefix is not in the list
	PodNameWhitelist []string `hcl:"pod_name_prefix_whitelist"`
}

// PSATAttestorConfig holds a map of clusters that uses cluster name as key
type PSATAttestorConfig struct {
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
}

type clusterConfig struct {
	kubeConfigFile  string
	k8sClient       client.K8SClient
	keys            []crypto.PublicKey
	serviceAccounts map[string]bool
	pods            map[string]bool
}

type psatAttestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig
}

func (p *PSATAttestorPlugin) Attest(stream nodeattestor.Attest_PluginStream) error {
	req, err := stream.Recv()
	if err != nil {
		return psatError.Wrap(err)
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	attestationData, err := p.ValidateAttestReq(req)
	if err != nil {
		return psatError.Wrap(err)
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
	err = p.VerifyTokenSignature(cluster.keys, token, claims)
	if err != nil {
		return psatError.Wrap(err)
	}

	if err := claims.Validate(jwt.Expected{
		Issuer: "api",
		Time:   time.Now(),
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

	serviceAccountName := fmt.Sprintf("%s:%s", claims.K8s.Namespace, claims.K8s.ServiceAccount.Name)
	if !cluster.serviceAccounts[serviceAccountName] {
		return psatError.New("%q is not a whitelisted service account", serviceAccountName)
	}

	isWhitelisted, podPrefix := isPodWhitelisted(claims.K8s.Pod.Name, cluster)
	if !isWhitelisted {
		return psatError.New("%q has not a whitelisted pod name prefix", claims.K8s.Pod.Name)
	}

	node, err := cluster.k8sClient.GetNode(claims.K8s.Namespace, claims.K8s.Pod.Name)
	if err != nil {
		return psatError.New("can't get node name from k8s api: %v", err)
	}

	return stream.Send(&nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: k8s.AgentID(pluginName, config.trustDomain, attestationData.Cluster, attestationData.UUID),
		Selectors: []*common.Selector{
			p.MakeSelector("cluster", attestationData.Cluster),
			p.MakeSelector("agent_ns", claims.K8s.Namespace),
			p.MakeSelector("agent_sa", claims.K8s.ServiceAccount.Name),
			p.MakeSelector("agent_pod", podPrefix),
			p.MakeSelector("agent_node", node),
		},
	})
}

func (p *PSATAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	hclConfig := new(PSATAttestorConfig)

	err := p.ValidateConfigReq(hclConfig, req)
	if err != nil {
		return nil, psatError.Wrap(err)
	}

	if len(hclConfig.Clusters) == 0 {
		return nil, psatError.New("configuration must have at least one cluster")
	}

	config := &psatAttestorConfig{
		trustDomain: req.GlobalConfig.TrustDomain,
		clusters:    make(map[string]*clusterConfig),
	}

	for name, cluster := range hclConfig.Clusters {
		if cluster.APIServerKeyFile == "" {
			return nil, psatError.New("cluster %q configuration missing api server keys file", name)
		}
		if len(cluster.ServiceAccountWhitelist) == 0 {
			return nil, psatError.New("cluster %q configuration must have at least one service account whitelisted", name)
		}
		if len(cluster.PodNameWhitelist) == 0 {
			return nil, psatError.New("cluster %q configuration must have at least one pod name prefix whitelisted", name)
		}

		keys, err := p.LoadServiceAccountKeys(cluster.APIServerKeyFile)
		if err != nil {
			return nil, psatError.New("failed to load cluster %q api server keys from %q: %v", name, cluster.APIServerKeyFile, err)
		}
		if len(keys) == 0 {
			return nil, psatError.New("cluster %q has no api server keys in %q", name, cluster.APIServerKeyFile)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range cluster.ServiceAccountWhitelist {
			serviceAccounts[serviceAccount] = true
		}

		pods := make(map[string]bool)
		for _, pod := range cluster.PodNameWhitelist {
			pods[pod] = true
		}

		config.clusters[name] = &clusterConfig{
			kubeConfigFile:  cluster.KubeConfigFile,
			k8sClient:       client.NewK8SClient(cluster.KubeConfigFile),
			keys:            keys,
			serviceAccounts: serviceAccounts,
			pods:            pods,
		}
	}

	p.setConfig(config)
	return &spi.ConfigureResponse{}, nil
}

func (p *PSATAttestorPlugin) getConfig() (*psatAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, psatError.New("not configured")
	}
	return p.config, nil
}

func (p *PSATAttestorPlugin) setConfig(config *psatAttestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func isPodWhitelisted(podFullName string, cluster *clusterConfig) (bool, string) {
	for whitelistedPodPrefix := range cluster.pods {
		if strings.HasPrefix(podFullName, whitelistedPodPrefix) {
			return true, whitelistedPodPrefix
		}
	}
	return false, ""
}
