package jointoken

import (
	"errors"
	"net/url"
	"path"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/proto/agent/nodeattestor"
	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

const (
	pluginName = "join_token"
)

type JoinTokenConfig struct {
	JoinToken   string `hcl:"join_token"`
	TrustDomain string `hcl:"trust_domain"`
}

type JoinTokenPlugin struct {
	joinToken   string
	trustDomain string

	mtx *sync.RWMutex
}

func (p *JoinTokenPlugin) spiffeID() *url.URL {
	spiffePath := path.Join("spire", "agent", pluginName, p.joinToken)
	id := &url.URL{
		Scheme: "spiffe",
		Host:   p.trustDomain,
		Path:   spiffePath,
	}

	return id
}

func (p *JoinTokenPlugin) FetchAttestationData(req *nodeattestor.FetchAttestationDataRequest) (*nodeattestor.FetchAttestationDataResponse, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.joinToken == "" {
		err := errors.New("Join token attestation attempted but no token provided")
		return &nodeattestor.FetchAttestationDataResponse{}, err
	}

	// FIXME: NA should be the one dictating type of this message
	// Change the proto to just take plain byte here
	data := &common.AttestedData{
		Type: pluginName,
		Data: []byte(p.joinToken),
	}

	resp := &nodeattestor.FetchAttestationDataResponse{
		AttestedData: data,
		SpiffeId:     p.spiffeID().String(),
	}

	return resp, nil
}

func (p *JoinTokenPlugin) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	resp := &spi.ConfigureResponse{}

	// Parse HCL config payload into config struct
	config := &JoinTokenConfig{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

	// Set local vars from config struct
	p.joinToken = config.JoinToken
	p.trustDomain = config.TrustDomain

	return resp, nil
}

func (*JoinTokenPlugin) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func New() nodeattestor.NodeAttestor {
	return &JoinTokenPlugin{
		mtx: &sync.RWMutex{},
	}
}
