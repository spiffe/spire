package nodeattestor

import (
	"github.com/spiffe/sri/pkg/common/plugin"
	"golang.org/x/net/context"
)

type grpcServer struct {
	delegate Interface
}

func (m *grpcServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return m.delegate.Configure(req)
}

func (m *grpcServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return m.delegate.GetPluginInfo(req)
}

func (m *grpcServer) Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error) {
	return m.delegate.Attest(req)
}

type grpcClient struct {
	client NodeAttestorClient
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

func (m *grpcClient) Attest(attestRequest *AttestRequest) (*AttestResponse, error) {
	response, err := m.client.Attest(context.Background(), attestRequest)
	return response, err
}
