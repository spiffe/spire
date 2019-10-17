package fakenoderesolver

import (
	"context"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/noderesolver"
)

const (
	defaultTrustDomain = "example.org"
)

type Config struct {
	// TrustDomain is the trust domain for SPIFFE IDs created by the attestor.
	// Defaults to "example.org" if empty.
	TrustDomain string

	// Selectors is a map from ID to a list of selector values to return with that id.
	Selectors map[string][]string
}

type NodeResolver struct {
	name   string
	config Config
}

var _ noderesolver.Plugin = (*NodeResolver)(nil)

func New(name string, config Config) *NodeResolver {
	if config.TrustDomain == "" {
		config.TrustDomain = defaultTrustDomain
	}
	return &NodeResolver{
		name:   name,
		config: config,
	}
}

func (p *NodeResolver) Resolve(ctx context.Context, req *noderesolver.ResolveRequest) (*noderesolver.ResolveResponse, error) {
	resp := &noderesolver.ResolveResponse{
		Map: map[string]*common.Selectors{},
	}

	for _, spiffeID := range req.BaseSpiffeIdList {
		var selectors []*common.Selector
		for _, value := range p.config.Selectors[spiffeID] {
			selectors = append(selectors, &common.Selector{
				Type:  p.name,
				Value: value,
			})
		}

		resp.Map[spiffeID] = &common.Selectors{
			Entries: selectors,
		}
	}

	return resp, nil
}

func (p *NodeResolver) Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return &plugin.ConfigureResponse{}, nil
}

func (p *NodeResolver) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}
