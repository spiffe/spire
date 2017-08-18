package upstreamca

import (
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/upstream_ca/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	UpstreamCaImpl UpstreamCa
}

func (m *GRPCServer) Configure(ctx context.Context, req *common.ConfigureRequest) (*common.ConfigureResponse, error) {
	response, err := m.UpstreamCaImpl.Configure(req.Configuration)
	return &common.ConfigureResponse{ErrorList: response}, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	response, err := m.UpstreamCaImpl.GetPluginInfo()
	return response, err
}

func (m *GRPCServer) SubmitCSR(ctx context.Context, req *sri_proto.SubmitCSRRequest) (*sri_proto.SubmitCSRResponse, error) {
	response, err := m.UpstreamCaImpl.SubmitCSR(req.Csr)
	return response, err
}

type GRPCClient struct {
	client sri_proto.UpstreamCAClient
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

func (m *GRPCClient) SubmitCSR(csr []byte) (*sri_proto.SubmitCSRResponse, error) {
	response, err := m.client.SubmitCSR(context.Background(), &sri_proto.SubmitCSRRequest{Csr: csr})
	return response, err
}
