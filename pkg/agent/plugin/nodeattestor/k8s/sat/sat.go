package sat

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/zeebo/errs"
)

const (
	pluginName = "k8s_sat"

	defaultTokenPath = "/run/secrets/kubernetes.io/serviceaccount/token" //nolint: gosec // false positive
)

var (
	satError = errs.Class("k8s-sat")
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *AttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, nodeattestor.PluginServer(p))
}

type AttestorConfig struct {
	Cluster   string `hcl:"cluster"`
	TokenPath string `hcl:"token_path"`
}

type attestorConfig struct {
	trustDomain string
	cluster     string
	tokenPath   string
}

type AttestorPlugin struct {
	mu     sync.RWMutex
	config *attestorConfig
}

func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

func (p *AttestorPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	token, err := loadTokenFromFile(config.tokenPath)
	if err != nil {
		return satError.New("unable to load token from %s: %v", config.tokenPath, err)
	}

	data, err := json.Marshal(k8s.SATAttestationData{
		Cluster: config.cluster,
		Token:   token,
	})
	if err != nil {
		return satError.Wrap(err)
	}

	return stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: pluginName,
			Data: data,
		},
	})
}

func (p *AttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (resp *spi.ConfigureResponse, err error) {
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
	if hclConfig.Cluster == "" {
		return nil, satError.New("configuration missing cluster")
	}

	config := &attestorConfig{
		trustDomain: req.GlobalConfig.TrustDomain,
		cluster:     hclConfig.Cluster,
		tokenPath:   hclConfig.TokenPath,
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
		return nil, satError.New("not configured")
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
