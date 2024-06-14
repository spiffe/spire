package k8spsat

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/apiserver"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	// Add auth providers to authenticate to clusters to verify tokens
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

const (
	pluginName = "k8s_psat"
)

var (
	defaultAudience = []string{"spire-server"}
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *AttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// AttestorConfig contains a map of clusters that uses cluster name as key
type AttestorConfig struct {
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
}

// ClusterConfig holds a single cluster configuration
type ClusterConfig struct {
	// Array of allowed service accounts names
	// Attestation is denied if coming from a service account that is not in the list
	ServiceAccountAllowList []string `hcl:"service_account_allow_list"`

	// Audience for PSAT token validation
	// If audience is not configured, defaultAudience will be used
	// If audience value is set to an empty slice, k8s apiserver audience will be used
	Audience *[]string `hcl:"audience"`

	// Kubernetes configuration file path
	// Used to create a k8s client to query the API server. If string is empty, in-cluster configuration is used
	KubeConfigFile string `hcl:"kube_config_file"`

	// Node labels that are allowed to use as selectors
	AllowedNodeLabelKeys []string `hcl:"allowed_node_label_keys"`

	// Pod labels that are allowed to use as selectors
	AllowedPodLabelKeys []string `hcl:"allowed_pod_label_keys"`
}

type attestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig
}

type clusterConfig struct {
	serviceAccounts      map[string]bool
	audience             []string
	client               apiserver.Client
	allowedNodeLabelKeys map[string]bool
	allowedPodLabelKeys  map[string]bool
}

// AttestorPlugin is a PSAT (Projected SAT) node attestor plugin
type AttestorPlugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	mu     sync.RWMutex
	config *attestorConfig
	log    hclog.Logger
}

// New creates a new PSAT node attestor plugin
func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

var _ nodeattestorv1.NodeAttestorServer = (*AttestorPlugin)(nil)

// SetLogger sets up plugin logging
func (p *AttestorPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *AttestorPlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	attestationData := new(k8s.PSATAttestationData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data payload: %v", err)
	}

	if attestationData.Cluster == "" {
		return status.Error(codes.InvalidArgument, "missing cluster in attestation data")
	}

	if attestationData.Token == "" {
		return status.Error(codes.InvalidArgument, "missing token in attestation data")
	}

	cluster := config.clusters[attestationData.Cluster]
	if cluster == nil {
		return status.Errorf(codes.InvalidArgument, "not configured for cluster %q", attestationData.Cluster)
	}

	tokenStatus, err := cluster.client.ValidateToken(stream.Context(), attestationData.Token, cluster.audience)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to validate token with TokenReview API: %v", err)
	}

	if !tokenStatus.Authenticated {
		return status.Error(codes.PermissionDenied, "token not authenticated according to TokenReview API")
	}

	namespace, serviceAccountName, err := k8s.GetNamesFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to parse username from token review status: %v", err)
	}
	fullServiceAccountName := fmt.Sprintf("%v:%v", namespace, serviceAccountName)

	if !cluster.serviceAccounts[fullServiceAccountName] {
		return status.Errorf(codes.PermissionDenied, "%q is not an allowed service account", fullServiceAccountName)
	}

	podName, err := k8s.GetPodNameFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get pod name from token review status: %v", err)
	}

	podUID, err := k8s.GetPodUIDFromTokenStatus(tokenStatus)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get pod UID from token review status: %v", err)
	}

	pod, err := cluster.client.GetPod(stream.Context(), namespace, podName)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get pod from k8s API server: %v", err)
	}

	node, err := cluster.client.GetNode(stream.Context(), pod.Spec.NodeName)
	if err != nil {
		return status.Errorf(codes.Internal, "fail to get node from k8s API server: %v", err)
	}

	nodeUID := string(node.UID)
	if nodeUID == "" {
		return status.Errorf(codes.Internal, "node UID is empty")
	}

	selectorValues := []string{
		k8s.MakeSelectorValue("cluster", attestationData.Cluster),
		k8s.MakeSelectorValue("agent_ns", namespace),
		k8s.MakeSelectorValue("agent_sa", serviceAccountName),
		k8s.MakeSelectorValue("agent_pod_name", podName),
		k8s.MakeSelectorValue("agent_pod_uid", podUID),
		k8s.MakeSelectorValue("agent_node_ip", pod.Status.HostIP),
		k8s.MakeSelectorValue("agent_node_name", pod.Spec.NodeName),
		k8s.MakeSelectorValue("agent_node_uid", nodeUID),
	}

	for key, value := range node.Labels {
		if cluster.allowedNodeLabelKeys[key] {
			selectorValues = append(selectorValues, k8s.MakeSelectorValue("agent_node_label", key, value))
		}
	}

	for key, value := range pod.Labels {
		if cluster.allowedPodLabelKeys[key] {
			selectorValues = append(selectorValues, k8s.MakeSelectorValue("agent_pod_label", key, value))
		}
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				CanReattest:    true,
				SpiffeId:       k8s.AgentID(pluginName, config.trustDomain, attestationData.Cluster, nodeUID),
				SelectorValues: selectorValues,
			},
		},
	})
}

func (p *AttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	hclConfig := new(AttestorConfig)

	if err := hcl.Decode(hclConfig, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}
	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}
	if req.CoreConfiguration.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "core configuration missing trust domain")
	}

	config := &attestorConfig{
		trustDomain: req.CoreConfiguration.TrustDomain,
		clusters:    make(map[string]*clusterConfig),
	}

	for name, cluster := range hclConfig.Clusters {
		if len(cluster.ServiceAccountAllowList) == 0 {
			return nil, status.Errorf(codes.InvalidArgument, "cluster %q configuration must have at least one service account allowed", name)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range cluster.ServiceAccountAllowList {
			serviceAccounts[serviceAccount] = true
		}

		var audience []string
		if cluster.Audience == nil {
			audience = defaultAudience
		} else {
			audience = *cluster.Audience
		}

		allowedNodeLabelKeys := make(map[string]bool)
		for _, label := range cluster.AllowedNodeLabelKeys {
			allowedNodeLabelKeys[label] = true
		}

		allowedPodLabelKeys := make(map[string]bool)
		for _, label := range cluster.AllowedPodLabelKeys {
			allowedPodLabelKeys[label] = true
		}

		config.clusters[name] = &clusterConfig{
			serviceAccounts:      serviceAccounts,
			audience:             audience,
			client:               apiserver.New(cluster.KubeConfigFile),
			allowedNodeLabelKeys: allowedNodeLabelKeys,
			allowedPodLabelKeys:  allowedPodLabelKeys,
		}
	}

	if len(hclConfig.Clusters) < 1 {
		p.log.Warn("No clusters configured, PSAT attestation is effectively disabled")
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func (p *AttestorPlugin) getConfig() (*attestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *AttestorPlugin) setConfig(config *attestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}
