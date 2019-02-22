package psat

import (
	"context"
	"crypto"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
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
	psatError = errs.Class("k8s-psat")
)

type ClusterConfig struct {
	ApiServerCertFile       string   `hcl:"api_server_cert_file"`
	ServiceAccountWhitelist []string `hcl:"service_account_whitelist"`
	PodNameWhitelist        []string `hcl:"pod_name_prefix_whitelist"`
}

type PSATAttestorConfig struct {
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
}

type clusterConfig struct {
	apiServerKey    crypto.PublicKey
	serviceAccounts map[string]bool
	pods            map[string]bool
}

type psatAttestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig
}

type PSATAttestorPlugin struct {
	*sat_common.CommonAttestorPlugin
	mu     sync.RWMutex
	config *psatAttestorConfig
}

var _ nodeattestor.Plugin = (*PSATAttestorPlugin)(nil)

func NewPSATAttestorPlugin() *PSATAttestorPlugin {
	return &PSATAttestorPlugin{
		CommonAttestorPlugin: sat_common.NewCommonAttestorPlugin(pluginName),
	}
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

	claims, err := verifyTokenSignature(cluster, token)
	if err != nil {
		return err
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

	if !isPodWhitelisted(claims.K8s.Pod.Name, cluster) {
		return psatError.New("%q has not a whitelisted pod name prefix", claims.K8s.Pod.Name)
	}

	return stream.Send(&nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: k8s.AgentID(pluginName, config.trustDomain, attestationData.Cluster, attestationData.UUID),
		Selectors: []*common.Selector{
			p.MakeSelector("cluster", attestationData.Cluster),
			p.MakeSelector("agent_ns", claims.K8s.Namespace),
			p.MakeSelector("agent_sa", claims.K8s.ServiceAccount.Name),
			p.MakeSelector("agent_pod", claims.K8s.Pod.Name),
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
		if cluster.ApiServerCertFile == "" {
			return nil, psatError.New("cluster %q configuration missing api server certificate file", name)
		}
		if len(cluster.ServiceAccountWhitelist) == 0 {
			return nil, psatError.New("cluster %q configuration must have at least one service account whitelisted", name)
		}
		cert, err := pemutil.LoadCertificate(cluster.ApiServerCertFile)
		if err != nil {
			return nil, psatError.New("failed to load cluster %q api server cert from %q: %v", name, cluster.ApiServerCertFile, err)
		}
		if cert.PublicKey == nil {
			return nil, psatError.New("nil public key in cluster %q apiserver certificate %q", name, cluster.ApiServerCertFile)
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
			apiServerKey:    cert.PublicKey,
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

func verifyTokenSignature(cluster *clusterConfig, token *jwt.JSONWebToken) (*k8s.PSATClaims, error) {
	claims := new(k8s.PSATClaims)
	err := token.Claims(cluster.apiServerKey, claims)
	if err != nil {
		return nil, psatError.New("unable to verify token: %v", err)
	}
	return claims, nil
}

func isPodWhitelisted(podFullName string, cluster *clusterConfig) bool {
	for whitelistedPodPrefix := range cluster.pods {
		if strings.HasPrefix(podFullName, whitelistedPodPrefix) {
			return true
		}
	}
	return false
}
