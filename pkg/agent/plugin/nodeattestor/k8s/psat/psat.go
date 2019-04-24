package psat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"

	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/kubelet"
	"github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
)

const (
	pluginName       = "k8s_psat"
	defaultTokenPath = "/var/run/secrets/tokens/spire-agent"
)

var (
	psatError = errs.Class("k8s-psat")
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *AttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, nodeattestor.PluginServer(p))
}

// New creates a new PSAT attestor plugin
func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

// AttestorPlugin is a PSAT (projected SAT) attestor plugin
type AttestorPlugin struct {
	mu            sync.RWMutex
	config        *attestorConfig
	kubeletClient kubelet.Client
}

// AttestorConfig holds configuration for AttestorPlugin
type AttestorConfig struct {
	// Cluster name where the agent lives
	Cluster string `hcl:"cluster"`

	// File path of PSAT
	TokenPath string `hcl:"token_path"`

	// KubeletCAPath is the path to the CA certificate for authenticating the
	// kubelet over the secure port. Required when using the secure port unless
	// SkipKubeletVerification is set. Defaults to the cluster trust bundle.
	KubeletCAPath string `hcl:"kubelet_ca_path"`

	// SkipKubeletVerification controls whether or not the plugin will
	// verify the certificate presented by the kubelet.
	SkipKubeletVerification bool `hcl:"skip_kubelet_verification"`

	// KubeletSecurePort defines the secure port for the kubelet
	// If empty it is set to default 10250
	KubeletSecurePort int `hcl:"kubelet_secure_port"`
}

type attestorConfig struct {
	trustDomain             string
	cluster                 string
	tokenPath               string
	kubeletCAPath           string
	skipKubeletVerification bool
	kubeletSecurePort       int
}

// FetchAttestationData loads PSAT from the configured path and send it to server node attestor
func (p *AttestorPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	tokenStr, err := loadTokenFromFile(config.tokenPath)
	if err != nil {
		return psatError.New("unable to load token from %s: %v", config.tokenPath, err)
	}

	token, err := jwt.ParseSigned(tokenStr)
	if err != nil {
		return psatError.New("error parsing token: %v", err)
	}

	// Since token validations are performed on the server side, UnsafeClaimsWithoutVerification is used
	claims := new(k8s.PSATClaims)
	err = token.UnsafeClaimsWithoutVerification(claims)
	if err != nil {
		return psatError.New("fail to get claims from token: %v", err)
	}

	if claims.K8s.Pod.UID == "" {
		return psatError.New("token claim pod UID is empty")
	}

	// Get node name from kubelet
	nodeName, err := getNodeNameFromKubelet(config, p.kubeletClient, claims.K8s.Pod.UID)
	if err != nil {
		return psatError.New("unable to get node name: %v", err)
	}

	data, err := json.Marshal(k8s.PSATAttestationData{
		Cluster: config.cluster,
		Token:   tokenStr,
	})
	if err != nil {
		return psatError.Wrap(err)
	}

	return stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: pluginName,
			Data: data,
		},
		SpiffeId: k8s.AgentID(pluginName, config.trustDomain, config.cluster, nodeName),
	})
}

// Configure decodes JSON config from request and populates AttestorPlugin with it
func (p *AttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (resp *spi.ConfigureResponse, err error) {
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
	if hclConfig.Cluster == "" {
		return nil, psatError.New("configuration missing cluster")
	}

	config := &attestorConfig{
		trustDomain:             req.GlobalConfig.TrustDomain,
		cluster:                 hclConfig.Cluster,
		tokenPath:               hclConfig.TokenPath,
		kubeletCAPath:           hclConfig.KubeletCAPath,
		skipKubeletVerification: hclConfig.SkipKubeletVerification,
		kubeletSecurePort:       hclConfig.KubeletSecurePort,
	}
	if config.tokenPath == "" {
		config.tokenPath = defaultTokenPath
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

func loadTokenFromFile(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", errs.Wrap(err)
	}
	if len(data) == 0 {
		return "", errs.New("%q is empty", path)
	}
	return string(data), nil
}

func getNodeNameFromKubelet(config *attestorConfig, kubeletClient kubelet.Client, podUID string) (string, error) {
	kubeletCliConf := &kubelet.ClientConfig{
		Secure:                  true,
		Port:                    config.kubeletSecurePort,
		KubeletCAPath:           config.kubeletCAPath,
		SkipKubeletVerification: config.skipKubeletVerification,
		TokenPath:               config.tokenPath,
	}

	var err error
	if kubeletClient == nil {
		kubeletClient, err = kubelet.LoadClient(kubeletCliConf)
		if err != nil {
			return "", fmt.Errorf("fail to load kubelet client: %v", err)
		}
	}

	podlist, err := kubeletClient.GetPodList()
	if err != nil {
		return "", fmt.Errorf("fail to get pod list from kubelet: %v", err)
	}

	for _, pod := range podlist.Items {
		if string(pod.UID) == podUID {
			nodeName := podlist.Items[0].Spec.NodeName
			if nodeName == "" {
				return "", errors.New("empty node name received from kubelet")
			}
			return nodeName, nil
		}
	}
	return "", fmt.Errorf("pod with UID: %q not found", podUID)
}
