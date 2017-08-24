package noderesolver

import (
	common "github.com/spiffe/sri/common"
	"github.com/spiffe/sri/common/plugin"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	NodeResolverImpl NodeResolver
}

func (m *GRPCServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	response, err := m.NodeResolverImpl.Configure(req.Configuration)
	return &sriplugin.ConfigureResponse{ErrorList: response}, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.NodeResolverImpl.GetPluginInfo()
	return response, err
}

func (m *GRPCServer) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	resolutionMap, err := m.NodeResolverImpl.Resolve(req.BaseSpiffeIdList)
	return &ResolveResponse{Map: resolutionMap}, err
}

type GRPCClient struct {
	client NodeResolverClient
}

func (m *GRPCClient) Configure(configuration string) ([]string, error) {
	response, err := m.client.Configure(context.Background(), &sriplugin.ConfigureRequest{configuration})
	if err != nil {
		return []string{}, err
	}
	return response.ErrorList, err
}

func (m *GRPCClient) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.client.GetPluginInfo(context.Background(), &sriplugin.GetPluginInfoRequest{})
	return response, err
}

func (m *GRPCClient) Resolve(physicalSpiffeIdList []string) (map[string]*common.Selectors, error) {
	node_res, err := m.client.Resolve(context.Background(), &ResolveRequest{
		physicalSpiffeIdList})
	return node_res.Map, err
}
