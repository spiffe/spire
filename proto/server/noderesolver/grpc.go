package noderesolver

import (
	"golang.org/x/net/context"

	"github.com/spiffe/spire/proto/common"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

type GRPCServer struct {
	NodeResolverImpl NodeResolver
}

func (m *GRPCServer) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	response, err := m.NodeResolverImpl.Configure(req)
	return response, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.NodeResolverImpl.GetPluginInfo(req)
}

func (m *GRPCServer) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	resolutionMap, err := m.NodeResolverImpl.Resolve(req.BaseSpiffeIdList)
	return &ResolveResponse{Map: resolutionMap}, err
}

type GRPCClient struct {
	client NodeResolverClient
}

func (m *GRPCClient) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	response, err := m.client.Configure(context.Background(), req)
	if err != nil {
		return response, err
	}
	return response, err
}

func (m *GRPCClient) GetPluginInfo(req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.client.GetPluginInfo(context.Background(), req)
}

func (m *GRPCClient) Resolve(physicalSpiffeIdList []string) (map[string]*common.Selectors, error) {
	node_res, err := m.client.Resolve(context.Background(), &ResolveRequest{
		physicalSpiffeIdList})
	return node_res.Map, err
}
