package jointoken

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/hashicorp/hcl"

	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
)

type JoinTokenConfig struct {
	JoinTokens map[string]int `hcl:"join_tokens"`
}

type JoinTokenPlugin struct {
	ConfigTime time.Time

	joinTokens  map[string]int
	trustDomain string

	mtx *sync.Mutex
}

func (p *JoinTokenPlugin) spiffeID(token string) *url.URL {
	spiffePath := path.Join("spiffe", "node-id", token)
	id := &url.URL{
		Scheme: "spiffe",
		Host:   p.trustDomain,
		Path:   spiffePath,
	}

	return id
}

func (p *JoinTokenPlugin) Attest(stream nodeattestor.Attest_PluginStream) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	joinToken := string(req.AttestationData.Data)

	// OK to echo the token here because it becomes public knowledge after attestation
	if req.AttestedBefore {
		err := fmt.Errorf("Join token %s has been used and is no longer valid", joinToken)
		return err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()
	tokenTTL, ok := p.joinTokens[joinToken]
	if !ok {
		err := errors.New("Unknown or expired join token")
		return err
	}

	// Check for expiration
	ttlDuration := time.Duration(tokenTTL) * time.Second
	if time.Since(p.ConfigTime) > ttlDuration {
		delete(p.joinTokens, joinToken)
		err := errors.New("Expired join token")
		return err
	}

	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: p.spiffeID(joinToken).String(),
	}
	delete(p.joinTokens, joinToken)

	return stream.Send(resp)
}

func (p *JoinTokenPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
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

	if req.GlobalConfig == nil {
		err := errors.New("global configuration is required")
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}
	if req.GlobalConfig.TrustDomain == "" {
		err := errors.New("trust_domain is required")
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

	// Set local vars from config struct
	p.mtx.Lock()
	defer p.mtx.Unlock()
	p.ConfigTime = time.Now()
	p.joinTokens = config.JoinTokens

	p.trustDomain = req.GlobalConfig.TrustDomain

	return &spi.ConfigureResponse{}, nil
}

func (*JoinTokenPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func New() nodeattestor.Plugin {
	return &JoinTokenPlugin{
		mtx: &sync.Mutex{},
	}
}
