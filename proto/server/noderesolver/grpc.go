package noderesolver

import (
	"golang.org/x/net/context"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

type GRPCClient struct {
	client NodeResolverClient
}

func (m *GRPCClient) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return m.client.Configure(ctx, req)
}

func (m *GRPCClient) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.client.GetPluginInfo(ctx, req)
}

func (m *GRPCClient) Resolve(ctx context.Context, req *ResolveRequest) (*ResolveResponse, error) {
	return m.client.Resolve(ctx, req)
}
