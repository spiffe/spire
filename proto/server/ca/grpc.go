package ca

import (
	"golang.org/x/net/context"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

type GRPCServer struct {
	ServerCaImpl ServerCa
}

func (m *GRPCServer) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return m.ServerCaImpl.Configure(req)
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.ServerCaImpl.GetPluginInfo(req)
}

func (m *GRPCServer) SignCsr(ctx context.Context, req *SignCsrRequest) (*SignCsrResponse, error) {
	return m.ServerCaImpl.SignCsr(req)
}

func (m *GRPCServer) GenerateCsr(ctx context.Context, req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	return m.ServerCaImpl.GenerateCsr(req)
}

func (m *GRPCServer) FetchCertificate(ctx context.Context, req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	return m.ServerCaImpl.FetchCertificate(req)
}

func (m *GRPCServer) LoadCertificate(ctx context.Context, req *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	return m.ServerCaImpl.LoadCertificate(req)
}

type GRPCClient struct {
	client ServerCAClient
}

func (m *GRPCClient) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return m.client.Configure(context.Background(), req)
}
func (m *GRPCClient) GetPluginInfo(req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.client.GetPluginInfo(context.Background(), req)
}

func (m *GRPCClient) SignCsr(request *SignCsrRequest) (response *SignCsrResponse, err error) {
	return m.client.SignCsr(context.Background(), request)
}

func (m *GRPCClient) GenerateCsr(req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	return m.client.GenerateCsr(context.Background(), req)
}

func (m *GRPCClient) FetchCertificate(req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	return m.client.FetchCertificate(context.Background(), req)
}

func (m *GRPCClient) LoadCertificate(request *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	response, err := m.client.LoadCertificate(context.Background(), request)
	return response, err
}
