package workloadattestor

import (
	"github.com/spiffe/sri/pkg/common/plugin"
	"golang.org/x/net/context"
)

type grpcServer struct {
	delegate Interface
}

func (m *grpcServer) Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error) {
	response, err := m.delegate.Attest(req)
	return response, err
}

func (m *grpcServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	response, err := m.delegate.Configure(req)
	return response, err
}

func (m *grpcServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.delegate.GetPluginInfo(req)
	return response, err
}

type grpcClient struct {
	client WorkloadAttestorClient
}

func (m *grpcClient) Attest(req *AttestRequest) (*AttestResponse, error) {
	res, err := m.client.Attest(context.Background(), req)
	return res, err
}

func (m *grpcClient) Configure(req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	res, err := m.client.Configure(context.Background(), req)
	return res, err
}

func (m *grpcClient) GetPluginInfo(req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	res, err := m.client.GetPluginInfo(context.Background(), req)
	return res, err
}
