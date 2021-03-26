package fakenoderesolver

import (
	"context"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/proto/spire/common"
	noderesolverv0 "github.com/spiffe/spire/proto/spire/plugin/server/noderesolver/v0"
	"github.com/spiffe/spire/test/plugintest"
)

func New(t *testing.T, name string, selectors map[string][]string) noderesolver.NodeResolver {
	server := noderesolverv0.NodeResolverPluginServer(&nodeResolver{
		name:      name,
		selectors: selectors,
	})

	v0 := new(noderesolver.V0)
	plugintest.Load(t, catalog.MakeBuiltIn(name, server), v0)
	return v0
}

type nodeResolver struct {
	noderesolverv0.UnimplementedNodeResolverServer

	name      string
	selectors map[string][]string
}

func (p *nodeResolver) Resolve(ctx context.Context, req *noderesolverv0.ResolveRequest) (*noderesolverv0.ResolveResponse, error) {
	resp := &noderesolverv0.ResolveResponse{
		Map: map[string]*common.Selectors{},
	}

	for _, spiffeID := range req.BaseSpiffeIdList {
		var selectors []*common.Selector
		for _, value := range p.selectors[spiffeID] {
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
