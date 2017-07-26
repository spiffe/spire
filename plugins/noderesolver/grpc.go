package noderesolver

import (
	"github.com/spiffe/control-plane/plugins/noderesolver/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	NodeResolutionImpl NodeResolution
}

func (m *GRPCServer) Resolve(ctx context.Context, req *proto.ResolveRequest) (*proto.ResolveResponse, error) {
	resolutionMap, err := m.NodeResolutionImpl.Resolve(req.PhysicalSpiffeIdList)
	return &proto.ResolveResponse{Map: resolutionMap}, err
}

func (m *GRPCServer) Configure(ctx context.Context, req *proto.ConfigureRequest) (*proto.Empty, error) {
	err := m.NodeResolutionImpl.Configure(req.Configuration)
	return &proto.Empty{}, err
}

type GRPCClient struct {
	client proto.NodeClient
}

func (m *GRPCClient) Resolve(physicalSpiffeIdList []string) (map[string]*proto.NodeResolutionList, error) {
	node_res, err := m.client.Resolve(context.Background(), &proto.ResolveRequest{
		physicalSpiffeIdList})
	return node_res.Map, err
}

func (m *GRPCClient) Configure(configuration string) error {
	_, err := m.client.Configure(context.Background(), &proto.ConfigureRequest{Configuration: configuration})
	return err
}
