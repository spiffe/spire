package nodeattestor

import (
	"golang.org/x/net/context"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

type GRPCServer struct {
	NodeAttestorImpl NodeAttestor
}

func (m *GRPCServer) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return m.NodeAttestorImpl.Configure(req)
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.NodeAttestorImpl.GetPluginInfo(req)
}

func (m *GRPCServer) Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error) {
	return m.NodeAttestorImpl.Attest(req)
}

type GRPCClient struct {
	client NodeAttestorClient
}

func (m *GRPCClient) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	response, err := m.client.Configure(context.Background(), req)
	if err != nil {
		return response, err
	}
	return response, err
}

func (m *GRPCClient) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	response, err := m.client.GetPluginInfo(context.Background(), &spi.GetPluginInfoRequest{})
	return response, err
}

func (m *GRPCClient) Attest(attestRequest *AttestRequest) (*AttestResponse, error) {
	response, err := m.client.Attest(context.Background(), attestRequest)
	return response, err
}
