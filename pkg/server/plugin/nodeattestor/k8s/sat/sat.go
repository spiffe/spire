package sat

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/gofrs/uuid"
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
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	pluginName = "k8s_sat"
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

	// TODO: Remove this in 1.1.0
	ServiceAccountAllowListDeprecated []string `hcl:"service_account_whitelist"`

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

type clusterConfig struct {
	serviceAccountKeys []crypto.PublicKey
	serviceAccounts    map[string]bool
	useTokenReviewAPI  bool
	client             apiserver.Client
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
	attested, err := p.IsAttested(stream.Context(), agentID)
	switch {
	case err != nil:
		return err
	case attested:
		return status.Error(codes.PermissionDenied, "SAT has already been used to attest an agent with the same UUID")
	}

	var namespace, serviceAccountName string
	if cluster.useTokenReviewAPI {
		// Empty audience is used since SAT does not support audiences
		tokenStatus, err := cluster.client.ValidateToken(stream.Context(), attestationData.Token, []string{})
		if err != nil {
			return status.Errorf(codes.Internal, "unable to validate token with TokenReview API: %v", err)
		}

		if !tokenStatus.Authenticated {
			return status.Error(codes.InvalidArgument, "token not authenticated according to TokenReview API")
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

		// TODO: service account tokens don't currently expire.... when they do, validate the time (with leeway)
		if err := claims.Validate(jwt.Expected{
			Issuer: "kubernetes/serviceaccount",
		}); err != nil {
			return status.Errorf(codes.InvalidArgument, "unable to validate token claims: %v", err)
		}

		if claims.Namespace == "" {
			return status.Error(codes.InvalidArgument, "token missing namespace claim")
		}

		if claims.ServiceAccountName == "" {
			return status.Error(codes.InvalidArgument, "token missing service account name claim")
		}

		namespace = claims.Namespace
		serviceAccountName = claims.ServiceAccountName
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
			},
		},
	})
}

func (p *AttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
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
		var apiserverClient apiserver.Client
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

		// TODO: Remove this in 1.1.0
		if len(cluster.ServiceAccountAllowListDeprecated) > 0 {
			p.log.Warn("The `service_account_whitelist` configurable is deprecated and will be removed in a future release. Please use `service_account_allow_list` instead.")
			cluster.ServiceAccountAllowList = cluster.ServiceAccountAllowListDeprecated
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

func verifyTokenSignature(keys []crypto.PublicKey, token *jwt.JSONWebToken, claims interface{}) (err error) {
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
	pemBytes, err := ioutil.ReadFile(path)
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
