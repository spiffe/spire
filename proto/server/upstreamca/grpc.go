package upstreamca

import (
	"golang.org/x/net/context"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

type GRPCServer struct {
	UpstreamCaImpl UpstreamCa
}

func (m *GRPCServer) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return m.UpstreamCaImpl.Configure(req)
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.UpstreamCaImpl.GetPluginInfo(req)
}

func (m *GRPCServer) SubmitCSR(ctx context.Context, req *SubmitCSRRequest) (*SubmitCSRResponse, error) {
	return m.UpstreamCaImpl.SubmitCSR(req)
}

type GRPCClient struct {
	client UpstreamCAClient
}

func (m *GRPCClient) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return m.client.Configure(context.Background(), req)
}

func (m *GRPCClient) GetPluginInfo(req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.client.GetPluginInfo(context.Background(), req)
}

func (m *GRPCClient) SubmitCSR(req *SubmitCSRRequest) (*SubmitCSRResponse, error) {
	return m.client.SubmitCSR(context.Background(), req)
}
