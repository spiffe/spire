package sat

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
	"io/ioutil"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/apiserver"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
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
	return builtin(New())
}

func builtin(p *AttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin("k8s_sat",
		nodeattestor.PluginServer(p),
	)
}

type ClusterConfig struct {
	// Path on disk to a PEM encoded file containing public keys used in validating tokens for that cluster
	// If use_token_review_api_validation is true, then this path is ignored and TokenReview API is used for validation
	ServiceAccountKeyFile string `hcl:"service_account_key_file"`

	// ServiceAccountWhitelist is a list of service account names, qualified by
	// namespace (for example, "default:blog" or "production:web") to allow for node attestation
	ServiceAccountWhitelist []string `hcl:"service_account_whitelist"`

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

	var namespace, serviceAccountName string
	if cluster.useTokenReviewAPI {
		// Empty audience is used since SAT does not support audiences
		tokenStatus, err := cluster.client.ValidateToken(attestationData.Token, []string{})
		if err != nil {
			return satError.New("unable to validate token with TokenReview API: %v", err)
		}

		if !tokenStatus.Authenticated {
			return satError.New("token not authenticated according to TokenReview API")
		}

		namespace, serviceAccountName, err = k8s.GetNamesFromTokenStatus(tokenStatus)
		if err != nil {
			return satError.New("fail to parse username from token review status: %v", err)
		}

	} else {

		token, err := jwt.ParseSigned(attestationData.Token)
		if err != nil {
			return satError.New("unable to parse token: %v", err)
		}

		claims := new(k8s.SATClaims)
		err = verifyTokenSignature(cluster.serviceAccountKeys, token, claims)
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

		namespace = claims.Namespace
		serviceAccountName = claims.ServiceAccountName
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

		var serviceAccountKeys []crypto.PublicKey
		var apiserverClient apiserver.Client
		var err error
		if cluster.UseTokenReviewAPI {
			apiserverClient = apiserver.New(cluster.KubeConfigFile)
		} else {
			if cluster.ServiceAccountKeyFile == "" {
				return nil, satError.New("cluster %q configuration missing service account key file", name)
			}

			serviceAccountKeys, err = loadServiceAccountKeys(cluster.ServiceAccountKeyFile)
			if err != nil {
				return nil, satError.New("failed to load cluster %q service account keys from %q: %v", name, cluster.ServiceAccountKeyFile, err)
			}

			if len(serviceAccountKeys) == 0 {
				return nil, satError.New("cluster %q has no service account keys in %q", name, cluster.ServiceAccountKeyFile)
			}
		}

		if len(cluster.ServiceAccountWhitelist) == 0 {
			return nil, satError.New("cluster %q configuration must have at least one service account whitelisted", name)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range cluster.ServiceAccountWhitelist {
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

func verifyTokenSignature(keys []crypto.PublicKey, token *jwt.JSONWebToken, claims interface{}) (err error) {
	var lastErr error
	for _, key := range keys {
		if err := token.Claims(key, claims); err != nil {
			lastErr = fmt.Errorf("unable to verify token: %v", err)
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("token signed by unknown authority")
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
