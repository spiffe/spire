package psat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/client"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	"github.com/zeebo/errs"

	k8s_auth "k8s.io/api/authentication/v1"
)

const (
	pluginName = "k8s_psat"
)

var (
	defaultAudience = []string{"spire-server"}
	defaultIssuer   = "api"
	psatError       = errs.Class("k8s-psat")
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *AttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName,
		nodeattestor.PluginServer(p),
	)
}

// AttestorConfig contains a map of clusters that uses cluster name as key
type AttestorConfig struct {
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
}

// ClusterConfig holds a single cluster configuration
type ClusterConfig struct {
	// Array of whitelisted service accounts names
	// Attestation is denied if comming from a service account that is not in the list
	ServiceAccountWhitelist []string `hcl:"service_account_whitelist"`

	// Audience for PSAT token validation
	// If audience is not configured, defaultAudience will be used
	// If audience value is set to an empty slice, k8s apiserver audience will be used
	Audience *[]string `hcl:"audience"`

	// Kubernetes configuration file path
	// Used to create a k8s client to query the API server. If path is empty, 'InClusterConfig' is used
	KubeConfigFile string `hcl:"kube_config_file"`
}

type attestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig
}

type clusterConfig struct {
	serviceAccounts map[string]bool
	audience        []string
	k8sClient       client.K8SClient
}

//AttestorPlugin is a PSAT (Projected SAT) node attestor plugin
type AttestorPlugin struct {
	mu     sync.RWMutex
	config *attestorConfig
}

// New creates a new PSAT node attestor plugin
func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

var _ nodeattestor.NodeAttestorServer = (*AttestorPlugin)(nil)

func (p *AttestorPlugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
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

	tokenStatus, err := cluster.k8sClient.ValidateToken(attestationData.Token, cluster.audience)
	if err != nil {
		return psatError.New("unable to validate token with TokenReview API: %v", err)
	}

	if !tokenStatus.Authenticated {
		return psatError.New("token not authenticated according to TokenReview API")
	}

	namespace, serviceAccountName, err := getNamesFromTokenStatus(tokenStatus)
	if err != nil {
		return psatError.New("fail to parse username from token review status: %v", err)
	}
	fullServiceAccountName := fmt.Sprintf("%v:%v", namespace, serviceAccountName)

	if !cluster.serviceAccounts[fullServiceAccountName] {
		return psatError.New("%q is not a whitelisted service account", fullServiceAccountName)
	}

	podName, err := getPodNameFromTokenStatus(tokenStatus)
	if err != nil {
		return psatError.New("fail to get pod name from token review status: %v", err)
	}

	podUID, err := getPodUIDFromTokenStatus(tokenStatus)
	if err != nil {
		return psatError.New("fail to get pod UID from token review status: %v", err)
	}

	node, err := cluster.k8sClient.GetNode(namespace, podName)
	if err != nil {
		return psatError.New("fail to get node name from k8s api: %v", err)
	}

	selectors := []*common.Selector{
		k8s.MakeSelector(pluginName, "cluster", attestationData.Cluster),
		k8s.MakeSelector(pluginName, "agent_ns", namespace),
		k8s.MakeSelector(pluginName, "agent_sa", serviceAccountName),
		k8s.MakeSelector(pluginName, "agent_pod_name", podName),
		k8s.MakeSelector(pluginName, "agent_pod_uid", podUID),
		k8s.MakeSelector(pluginName, "agent_node_name", node),
	}

	return stream.Send(&nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: k8s.AgentID(pluginName, config.trustDomain, attestationData.Cluster, node),
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
		if len(cluster.ServiceAccountWhitelist) == 0 {
			return nil, psatError.New("cluster %q configuration must have at least one service account whitelisted", name)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range cluster.ServiceAccountWhitelist {
			serviceAccounts[serviceAccount] = true
		}

		var audience []string
		if cluster.Audience == nil {
			audience = defaultAudience
		} else {
			audience = *cluster.Audience
		}

		config.clusters[name] = &clusterConfig{
			serviceAccounts: serviceAccounts,
			audience:        audience,
			k8sClient:       client.NewK8SClient(cluster.KubeConfigFile),
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

// getNamesFromTokenStatus parses a fully qualified k8s username like: 'system:serviceaccount:spire:spire-agent'
// from tokenStatus. The string is splitted and the last two names are returned: namespace and service account name
func getNamesFromTokenStatus(tokenStatus *k8s_auth.TokenReviewStatus) (string, string, error) {
	username := tokenStatus.User.Username
	if username == "" {
		return "", "", errors.New("empty username")
	}

	names := strings.Split(username, ":")
	if len(names) != 4 {
		return "", "", fmt.Errorf("unexpected username format: %v", username)
	}

	if names[2] == "" {
		return "", "", fmt.Errorf("missing namespace")
	}

	if names[3] == "" {
		return "", "", fmt.Errorf("missing service account name")
	}

	return names[2], names[3], nil
}

// getPodNameFromTokenStatus extracts pod name from a tokenReviewStatus type
func getPodNameFromTokenStatus(tokenStatus *k8s_auth.TokenReviewStatus) (string, error) {
	podName, ok := tokenStatus.User.Extra["authentication.kubernetes.io/pod-name"]
	if !ok {
		return "", errors.New("missing pod name")
	}

	if len(podName) != 1 {
		return "", fmt.Errorf("expected 1 name but got: %d", len(podName))
	}

	if podName[0] == "" {
		return "", errors.New("pod name is empty")
	}

	return podName[0], nil
}

// getPodUIDFromTokenStatus extracts pod UID from a tokenReviewStatus type
func getPodUIDFromTokenStatus(tokenStatus *k8s_auth.TokenReviewStatus) (string, error) {
	podUID, ok := tokenStatus.User.Extra["authentication.kubernetes.io/pod-uid"]
	if !ok {
		return "", errors.New("missing pod UID")
	}

	if len(podUID) != 1 {
		return "", fmt.Errorf("expected 1 UID but got: %d", len(podUID))
	}

	if podUID[0] == "" {
		return "", errors.New("pod UID is empty")
	}

	return podUID[0], nil
}
