package noderesolver

import (
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/node_resolver/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	NodeResolutionImpl NodeResolution
}

func (m *GRPCServer) Configure(ctx context.Context, req *common.ConfigureRequest) (*common.ConfigureResponse, error) {
	response, err := m.NodeResolutionImpl.Configure(req.Configuration)
	return &common.ConfigureResponse{ErrorList: response}, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	response, err := m.NodeResolutionImpl.GetPluginInfo()
	return response, err
}

func (m *GRPCServer) Resolve(ctx context.Context, req *control_plane_proto.ResolveRequest) (*control_plane_proto.ResolveResponse, error) {
	resolutionMap, err := m.NodeResolutionImpl.Resolve(req.BaseSpiffeIdList)
	return &control_plane_proto.ResolveResponse{Map: resolutionMap}, err
}

type GRPCClient struct {
	client control_plane_proto.NodeResolverClient
}

func (m *GRPCClient) Configure(configuration string) ([]string, error) {
	response, err := m.client.Configure(context.Background(), &common.ConfigureRequest{configuration})
	if err != nil {
		return []string{}, err
	}
	return response.ErrorList, err
}

func (m *GRPCClient) GetPluginInfo() (*common.GetPluginInfoResponse, error) {
	response, err := m.client.GetPluginInfo(context.Background(), &common.GetPluginInfoRequest{})
	return response, err
}

func (m *GRPCClient) Resolve(physicalSpiffeIdList []string) (map[string]*control_plane_proto.NodeResolutionList, error) {
	node_res, err := m.client.Resolve(context.Background(), &control_plane_proto.ResolveRequest{
		physicalSpiffeIdList})
	return node_res.Map, err
}
