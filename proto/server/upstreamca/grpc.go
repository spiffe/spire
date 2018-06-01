package upstreamca

import (
	"golang.org/x/net/context"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

type GRPCClient struct {
	client UpstreamCAClient
}

func (m *GRPCClient) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return m.client.Configure(ctx, req)
}

func (m *GRPCClient) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.client.GetPluginInfo(ctx, req)
}

func (m *GRPCClient) SubmitCSR(ctx context.Context, req *SubmitCSRRequest) (*SubmitCSRResponse, error) {
	return m.client.SubmitCSR(ctx, req)
}
