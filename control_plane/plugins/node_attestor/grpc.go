package control_plane_nodeattestor

import (
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/node_attestor/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	NodeAttestorImpl NodeAttestor
}

func (m *GRPCServer) Configure(ctx context.Context, req *common.ConfigureRequest) (*common.ConfigureResponse, error) {
	response, err := m.NodeAttestorImpl.Configure(req.Configuration)
	return &common.ConfigureResponse{ErrorList: response}, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	response, err := m.NodeAttestorImpl.GetPluginInfo()
	return response, err
}

func (m *GRPCServer) Attest(ctx context.Context, req *control_plane_proto.AttestRequest) (*control_plane_proto.AttestResponse, error) {
	response, err := m.NodeAttestorImpl.Attest(req)
	return response, err
}

type GRPCClient struct {
	client control_plane_proto.NodeAttestorClient
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

func (m *GRPCClient) Attest(attestRequest *control_plane_proto.AttestRequest) (*control_plane_proto.AttestResponse, error) {
	response, err := m.client.Attest(context.Background(), attestRequest)
	return response, err
}
