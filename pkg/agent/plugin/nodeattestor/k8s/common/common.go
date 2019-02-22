package common

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

type CommonAttestorConfig struct {
	Cluster   string `hcl:"cluster"`
	TokenPath string `hcl:"token_path"`
}

type commonAttestorConfig struct {
	trustDomain string
	cluster     string
	tokenPath   string
}

type CommonAttestorPlugin struct {
	mu               sync.RWMutex
	config           *commonAttestorConfig
	pluginName       string
	defaultTokenPath string
	commonError      errs.Class

	hooks struct {
		newUUID func() (string, error)
	}
}

func NewCommonAttestorPlugin(pluginName string, defaultTokenPath string, errClassName string) *CommonAttestorPlugin {
	p := &CommonAttestorPlugin{
		pluginName:       pluginName,
		defaultTokenPath: defaultTokenPath,
		commonError:      errs.Class(errClassName),
	}

	p.hooks.newUUID = func() (string, error) {
		u, err := uuid.NewV4()
		if err != nil {
			return "", err
		}
		return u.String(), nil
	}

	return p
}

func (p *CommonAttestorPlugin) FetchAttestationData(stream nodeattestor.FetchAttestationData_PluginStream) error {
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
		return p.commonError.New("unable to load token from %s: %v", config.tokenPath, err)
	}

	data, err := json.Marshal(k8s.SATAttestationData{
		Cluster: config.cluster,
		UUID:    uuid,
		Token:   token,
	})
	if err != nil {
		return p.commonError.Wrap(err)
	}

	return stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: p.pluginName,
			Data: data,
		},
		SpiffeId: k8s.AgentID(p.pluginName, config.trustDomain, config.cluster, uuid),
	})
}

func (p *CommonAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (resp *spi.ConfigureResponse, err error) {
	hclConfig := new(CommonAttestorConfig)
	if err := hcl.Decode(hclConfig, req.Configuration); err != nil {
		return nil, p.commonError.New("unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, p.commonError.New("global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, p.commonError.New("global configuration missing trust domain")
	}
	if hclConfig.Cluster == "" {
		return nil, p.commonError.New("configuration missing cluster")
	}

	config := &commonAttestorConfig{
		trustDomain: req.GlobalConfig.TrustDomain,
		cluster:     hclConfig.Cluster,
		tokenPath:   hclConfig.TokenPath,
	}
	if config.tokenPath == "" {
		config.tokenPath = p.defaultTokenPath
	}

	p.setConfig(config)
	return &spi.ConfigureResponse{}, nil
}

func (p *CommonAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *CommonAttestorPlugin) getConfig() (*commonAttestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, p.commonError.New("not configured")
	}
	return p.config, nil
}

func (p *CommonAttestorPlugin) setConfig(config *commonAttestorConfig) {
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
