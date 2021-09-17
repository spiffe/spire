package fakenoderesolver

import (
	"context"
	"testing"

	noderesolverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/noderesolver/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/test/plugintest"
)

func New(t *testing.T, name string, selectors map[string][]string) noderesolver.NodeResolver {
	server := noderesolverv1.NodeResolverPluginServer(&nodeResolver{
		selectors: selectors,
	})

	v1 := new(noderesolver.V1)
	plugintest.Load(t, catalog.MakeBuiltIn(name, server), v1)
	return v1
}

type nodeResolver struct {
	noderesolverv1.UnimplementedNodeResolverServer

	selectors map[string][]string
}

func (p *nodeResolver) Resolve(ctx context.Context, req *noderesolverv1.ResolveRequest) (*noderesolverv1.ResolveResponse, error) {
	return &noderesolverv1.ResolveResponse{
		SelectorValues: p.selectors[req.AgentId],
	}, nil
}
