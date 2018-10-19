package k8s

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"sync"

	"github.com/hashicorp/hcl"
	uuid "github.com/satori/go.uuid"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/zeebo/errs"
)

const (
	pluginName = "k8s_sat"

	defaultTokenPath = "/run/secrets/kubernetes.io/serviceaccount/token"
)

var (
	satError = errs.Class("k8s-sat")
)

type SATAttestorConfig struct {
	Cluster   string `hcl:"cluster"`
	TokenPath string `hcl:"token_path"`
}

type satAttestorConfig struct {
	trustDomain string
	cluster     string
	tokenPath   string
}

type SATAttestorPlugin struct {
	mu     sync.RWMutex
	config *satAttestorConfig

	hooks struct {
		newUUID func() string
	}
}

var _ nodeattestor.Plugin = (*SATAttestorPlugin)(nil)

func NewSATAttestorPlugin() *SATAttestorPlugin {
	p := &SATAttestorPlugin{}
	p.hooks.newUUID = func() string {
		return uuid.NewV4().String()
	}
	return p
}

func (p *SATAttestorPlugin) FetchAttestationData(stream nodeattestor.FetchAttestationData_PluginStream) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	uuid := p.hooks.newUUID()

	token, err := loadTokenFromFile(config.tokenPath)
	if err != nil {
		return satError.New("unable to load token from %s: %v", config.tokenPath, err)
	}

	data, err := json.Marshal(k8s.SATAttestationData{
		Cluster: config.cluster,
		UUID:    uuid,
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
		SpiffeId: k8s.AgentID(config.trustDomain, config.cluster, uuid),
	})
}

func (p *SATAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (resp *spi.ConfigureResponse, err error) {
	hclConfig := new(SATAttestorConfig)
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

	config := &satAttestorConfig{
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

func (p *SATAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *SATAttestorPlugin) getConfig() (*satAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, satError.New("not configured")
	}
	return p.config, nil
}

func (p *SATAttestorPlugin) setConfig(config *satAttestorConfig) {
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
