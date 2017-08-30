package upstreamca

import (
	"github.com/spiffe/sri/pkg/common/plugin"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	UpstreamCaImpl UpstreamCa
}

func (m *GRPCServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return m.UpstreamCaImpl.Configure(req)
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.UpstreamCaImpl.GetPluginInfo()
	return response, err
}

func (m *GRPCServer) SubmitCSR(ctx context.Context, req *SubmitCSRRequest) (*SubmitCSRResponse, error) {
	return m.UpstreamCaImpl.SubmitCSR(req)
}

type GRPCClient struct {
	client UpstreamCAClient
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

func (m *GRPCClient) SubmitCSR(csr []byte) (*SubmitCSRResponse, error) {
	response, err := m.client.SubmitCSR(context.Background(), &SubmitCSRRequest{Csr: csr})
	return response, err
}
