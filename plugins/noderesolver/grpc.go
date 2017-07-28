package noderesolver

import (
	common "github.com/spiffe/control-plane/plugins/common/proto"
	"github.com/spiffe/control-plane/plugins/noderesolver/proto"
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

func (m *GRPCServer) Resolve(ctx context.Context, req *proto.ResolveRequest) (*proto.ResolveResponse, error) {
	resolutionMap, err := m.NodeResolutionImpl.Resolve(req.PhysicalSpiffeIdList)
	return &proto.ResolveResponse{Map: resolutionMap}, err
}

type GRPCClient struct {
	client proto.NodeClient
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

func (m *GRPCClient) Resolve(physicalSpiffeIdList []string) (map[string]*proto.NodeResolutionList, error) {
	node_res, err := m.client.Resolve(context.Background(), &proto.ResolveRequest{
		physicalSpiffeIdList})
	return node_res.Map, err
}
