package sat

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"sync"

	"github.com/gofrs/uuid"
	"github.com/hashicorp/hcl"
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

	hooks struct {
		newUUID func() (string, error)
	}
}

var _ nodeattestor.Plugin = (*AttestorPlugin)(nil)

func NewAttestorPlugin() *AttestorPlugin {
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

func (p *AttestorPlugin) FetchAttestationData(stream nodeattestor.FetchAttestationData_PluginStream) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	uuid, err := p.hooks.newUUID()
	if err != nil {
		return err
	}

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
		SpiffeId: k8s.AgentID(pluginName, config.trustDomain, config.cluster, uuid),
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
