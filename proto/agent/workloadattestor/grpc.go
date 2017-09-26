package workloadattestor

import (
	"golang.org/x/net/context"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

type GRPCServer struct {
	WorkloadAttestorImpl WorkloadAttestor
}

func (m *GRPCServer) Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error) {
	response, err := m.WorkloadAttestorImpl.Attest(req)
	return response, err
}

func (m *GRPCServer) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	response, err := m.WorkloadAttestorImpl.Configure(req)
	return response, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	response, err := m.WorkloadAttestorImpl.GetPluginInfo(req)
	return response, err
}

type GRPCClient struct {
	client WorkloadAttestorClient
}

func (m *GRPCClient) Attest(req *AttestRequest) (*AttestResponse, error) {
	res, err := m.client.Attest(context.Background(), req)
	return res, err
}

func (m *GRPCClient) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	res, err := m.client.Configure(context.Background(), req)
	return res, err
}

func (m *GRPCClient) GetPluginInfo(req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	res, err := m.client.GetPluginInfo(context.Background(), req)
	return res, err
}
