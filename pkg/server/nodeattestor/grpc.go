package nodeattestor

import (
	"github.com/spiffe/sri/pkg/common/plugin"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	NodeAttestorImpl NodeAttestor
}

func (m *GRPCServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	response, err := m.NodeAttestorImpl.Configure(req.Configuration)
	return &sriplugin.ConfigureResponse{ErrorList: response}, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.NodeAttestorImpl.GetPluginInfo()
	return response, err
}

func (m *GRPCServer) Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error) {
	response, err := m.NodeAttestorImpl.Attest(req)
	return response, err
}

type GRPCClient struct {
	client NodeAttestorClient
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

func (m *GRPCClient) Attest(attestRequest *AttestRequest) (*AttestResponse, error) {
	response, err := m.client.Attest(context.Background(), attestRequest)
	return response, err
}
