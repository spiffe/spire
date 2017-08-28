package noderesolver

import (
	"github.com/spiffe/sri/pkg/common"
	"github.com/spiffe/sri/pkg/common/plugin"
	"golang.org/x/net/context"
)

type grpcServer struct {
	delegate Interface
}

func (m *grpcServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	response, err := m.delegate.Configure(req.Configuration)
	return &sriplugin.ConfigureResponse{ErrorList: response}, err
}

func (m *grpcServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.delegate.GetPluginInfo()
	return response, err
}

func (m *grpcServer) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	resolutionMap, err := m.delegate.Resolve(req.BaseSpiffeIdList)
	return &ResolveResponse{Map: resolutionMap}, err
}

type grpcClient struct {
	client NodeResolverClient
}

func (m *grpcClient) Configure(configuration string) ([]string, error) {
	response, err := m.client.Configure(context.Background(), &sriplugin.ConfigureRequest{configuration})
	if err != nil {
		return []string{}, err
	}
	return response.ErrorList, err
}

func (m *grpcClient) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.client.GetPluginInfo(context.Background(), &sriplugin.GetPluginInfoRequest{})
	return response, err
}

func (m *grpcClient) Resolve(physicalSpiffeIdList []string) (map[string]*common.Selectors, error) {
	node_res, err := m.client.Resolve(context.Background(), &ResolveRequest{
		physicalSpiffeIdList})
	return node_res.Map, err
}
