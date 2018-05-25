package ca

import (
	"golang.org/x/net/context"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

type GRPCClient struct {
	client ServerCAClient
}

func (m *GRPCClient) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return m.client.Configure(ctx, req)
}
func (m *GRPCClient) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.client.GetPluginInfo(ctx, req)
}

func (m *GRPCClient) SignCsr(ctx context.Context, req *SignCsrRequest) (response *SignCsrResponse, err error) {
	return m.client.SignCsr(ctx, req)
}

func (m *GRPCClient) GenerateCsr(ctx context.Context, req *GenerateCsrRequest) (*GenerateCsrResponse, error) {
	return m.client.GenerateCsr(ctx, req)
}

func (m *GRPCClient) FetchCertificate(ctx context.Context, req *FetchCertificateRequest) (*FetchCertificateResponse, error) {
	return m.client.FetchCertificate(ctx, req)
}

func (m *GRPCClient) LoadCertificate(ctx context.Context, req *LoadCertificateRequest) (*LoadCertificateResponse, error) {
	return m.client.LoadCertificate(ctx, req)
}
