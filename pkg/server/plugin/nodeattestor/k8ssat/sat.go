package k8ssat

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gofrs/uuid/v5"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/apiserver"
	nodeattestorbase "github.com/spiffe/spire/pkg/server/plugin/nodeattestor/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	authv1 "k8s.io/api/authentication/v1"
)

const (
	pluginName = "k8s_sat"

	// If there are clock differences between the agent and server then token
	// validation may fail unless we give a little leeway.
	tokenLeeway = time.Minute * 5
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *AttestorPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn("k8s_sat",
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type ClusterConfig struct {
	// Path on disk to a PEM encoded file containing public keys used in validating tokens for that cluster
	// If use_token_review_api_validation is true, then this path is ignored and TokenReview API is used for validation
	ServiceAccountKeyFile string `hcl:"service_account_key_file"`

	// ServiceAccountAllowList is a list of service account names, qualified by
	// namespace (for example, "default:blog" or "production:web") to allow for node attestation
	ServiceAccountAllowList []string `hcl:"service_account_allow_list"`

	// UseTokenReviewAPI
	//   If true token review API will be used for token validation
	//   If false ServiceAccountKeyFile will be used for token validation
	UseTokenReviewAPI bool `hcl:"use_token_review_api_validation"`

	// Kubernetes configuration file path
	// Used to create a client to query the Kubernetes API server. If string is empty, in-cluster configuration is used
	KubeConfigFile string `hcl:"kube_config_file"`
}

type AttestorConfig struct {
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
}

type apiServerClient interface {
	ValidateToken(ctx context.Context, token string, audiences []string) (*authv1.TokenReviewStatus, error)
}

type clusterConfig struct {
	serviceAccountKeys []crypto.PublicKey
	serviceAccounts    map[string]bool
	useTokenReviewAPI  bool
	client             apiServerClient
}

type attestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig
}

type AttestorPlugin struct {
	nodeattestorbase.Base
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	mu     sync.RWMutex
	config *attestorConfig
	log    hclog.Logger

	hooks struct {
		newUUID func() (string, error)
		now     func() time.Time
	}
}

func New() *AttestorPlugin {
	p := &AttestorPlugin{}
	p.hooks.newUUID = func() (string, error) {
		u, err := uuid.NewV4()
		if err != nil {
			return "", err
		}
		return u.String(), nil
	}
	p.hooks.now = time.Now
	return p
}

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

	attestationData := new(k8s.SATAttestationData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal attestation data: %v", err)
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

	uuid, err := p.hooks.newUUID()
	if err != nil {
		return err
	}

	// It is incredibly unlikely the agent will have already attested since we
	// generate a new UUID on each attestation but just in case...
	agentID := k8s.AgentID(pluginName, config.trustDomain, attestationData.Cluster, uuid)
	if err := p.AssessTOFU(stream.Context(), agentID, p.log); err != nil {
		return err
	}

	var namespace, serviceAccountName string
	if cluster.useTokenReviewAPI {
		// Empty audience is used since SAT does not support audiences
		tokenStatus, err := cluster.client.ValidateToken(stream.Context(), attestationData.Token, []string{})
		if err != nil {
			return status.Errorf(codes.Internal, "unable to validate token with TokenReview API: %v", err)
		}

		if !tokenStatus.Authenticated {
			return status.Error(codes.PermissionDenied, "token not authenticated according to TokenReview API")
		}

		namespace, serviceAccountName, err = k8s.GetNamesFromTokenStatus(tokenStatus)
		if err != nil {
			return status.Errorf(codes.Internal, "fail to parse username from token review status: %v", err)
		}
	} else {
		token, err := jwt.ParseSigned(attestationData.Token)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "unable to parse token: %v", err)
		}

		claims := new(k8s.SATClaims)
		err = verifyTokenSignature(cluster.serviceAccountKeys, token, claims)
		if err != nil {
			return err
		}
		if !claims.Expiry.Time().IsZero() {
			// This is an indication that this may be a projected service account token
			p.log.Warn("The service account token has an expiration time, which is an indication that may be a projected service account token. If your cluster supports Service Account Token Volume Projection you should instead use the `k8s_psat` attestor as soon as possible. The `k8s_sat` attestor has been deprecated in favor of the `k8s_psat` attestor and will be removed in a future release. Please look at https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_k8s_sat.md#security-considerations for details about security considerations when using the `k8s_sat` attestor.")

			// Validate the time with leeway
			if err := claims.ValidateWithLeeway(jwt.Expected{
				Time: p.hooks.now(),
			}, tokenLeeway); err != nil {
				return status.Errorf(codes.InvalidArgument, "unable to validate token claims: %v", err)
			}
		}

		namespace, serviceAccountName, err = p.getNamesFromClaims(claims)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "error parsing token claims: %v", err)
		}
	}

	fullServiceAccountName := fmt.Sprintf("%v:%v", namespace, serviceAccountName)
	if !cluster.serviceAccounts[fullServiceAccountName] {
		return status.Errorf(codes.PermissionDenied, "%q is not an allowed service account", fullServiceAccountName)
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId: agentID,
				SelectorValues: []string{
					k8s.MakeSelectorValue("cluster", attestationData.Cluster),
					k8s.MakeSelectorValue("agent_ns", namespace),
					k8s.MakeSelectorValue("agent_sa", serviceAccountName),
				},
				CanReattest: false,
			},
		},
	})
}

// getNamesFromClaims parses claims from a k8s.SATClaims struct
// to extract the namespace and service account name
func (p *AttestorPlugin) getNamesFromClaims(claims *k8s.SATClaims) (namespace string, serviceAccountName string, err error) {
	if claims.Namespace == "" {
		if claims.K8s.Namespace == "" {
			return "", "", errors.New("token missing namespace claim")
		}
		namespace = claims.K8s.Namespace
	} else {
		if claims.K8s.Namespace != "" {
			return "", "", errors.New("malformed token: namespace found in two claims")
		}
		namespace = claims.Namespace
	}

	if claims.ServiceAccountName == "" {
		if claims.K8s.ServiceAccount.Name == "" {
			return "", "", errors.New("token missing service account name claim")
		}
		serviceAccountName = claims.K8s.ServiceAccount.Name
	} else {
		if claims.K8s.ServiceAccount.Name != "" {
			return "", "", errors.New("malformed token: service account name found in two claims")
		}
		serviceAccountName = claims.ServiceAccountName
	}

	return namespace, serviceAccountName, nil
}

func (p *AttestorPlugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	p.log.Warn(fmt.Sprintf("The %q node attestor plugin has been deprecated in favor of the \"k8s_psat\" plugin and will be removed in a future release", pluginName))

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

	if len(hclConfig.Clusters) == 0 {
		return nil, status.Error(codes.InvalidArgument, "configuration must have at least one cluster")
	}

	config := &attestorConfig{
		trustDomain: req.CoreConfiguration.TrustDomain,
		clusters:    make(map[string]*clusterConfig),
	}
	config.trustDomain = req.CoreConfiguration.TrustDomain
	for name, cluster := range hclConfig.Clusters {
		var serviceAccountKeys []crypto.PublicKey
		var apiserverClient apiServerClient
		var err error
		if cluster.UseTokenReviewAPI {
			apiserverClient = apiserver.New(cluster.KubeConfigFile)
		} else {
			if cluster.ServiceAccountKeyFile == "" {
				return nil, status.Errorf(codes.InvalidArgument, "cluster %q configuration missing service account key file", name)
			}

			serviceAccountKeys, err = loadServiceAccountKeys(cluster.ServiceAccountKeyFile)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "failed to load cluster %q service account keys from %q: %v", name, cluster.ServiceAccountKeyFile, err)
			}

			if len(serviceAccountKeys) == 0 {
				return nil, status.Errorf(codes.InvalidArgument, "cluster %q has no service account keys in %q", name, cluster.ServiceAccountKeyFile)
			}
		}

		if len(cluster.ServiceAccountAllowList) == 0 {
			return nil, status.Errorf(codes.InvalidArgument, "cluster %q configuration must have at least one service account allowed", name)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range cluster.ServiceAccountAllowList {
			serviceAccounts[serviceAccount] = true
		}

		config.clusters[name] = &clusterConfig{
			serviceAccountKeys: serviceAccountKeys,
			serviceAccounts:    serviceAccounts,
			useTokenReviewAPI:  cluster.UseTokenReviewAPI,
			client:             apiserverClient,
		}
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func (p *AttestorPlugin) getConfig() (*attestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *AttestorPlugin) setConfig(config *attestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func verifyTokenSignature(keys []crypto.PublicKey, token *jwt.JSONWebToken, claims any) (err error) {
	var lastErr error
	for _, key := range keys {
		if err := token.Claims(key, claims); err != nil {
			lastErr = status.Errorf(codes.InvalidArgument, "unable to verify token: %v", err)
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = status.Error(codes.InvalidArgument, "token signed by unknown authority")
	}
	return lastErr
}

func loadServiceAccountKeys(path string) ([]crypto.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var keys []crypto.PublicKey
	for {
		var pemBlock *pem.Block
		pemBlock, pemBytes = pem.Decode(pemBytes)
		if pemBlock == nil {
			return keys, nil
		}
		key, err := decodeKeyBlock(pemBlock)
		if err != nil {
			return nil, err
		}
		if key != nil {
			keys = append(keys, key)
		}
	}
}

func decodeKeyBlock(block *pem.Block) (crypto.PublicKey, error) {
	var key crypto.PublicKey
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = cert.PublicKey
	case "RSA PUBLIC KEY":
		rsaKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = rsaKey
	case "PUBLIC KEY":
		pkixKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = pkixKey
	default:
		return nil, nil
	}

	if !isSupportedKey(key) {
		return nil, fmt.Errorf("unsupported %T in %s block", key, block.Type)
	}
	return key, nil
}

func isSupportedKey(key crypto.PublicKey) bool {
	switch key.(type) {
	case *rsa.PublicKey:
		return true
	case *ecdsa.PublicKey:
		return true
	default:
		return false
	}
}
