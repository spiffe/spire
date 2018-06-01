package nodeattestor

import (
	spi "github.com/spiffe/spire/proto/common/plugin"
	"golang.org/x/net/context"
)

type GRPCClient struct {
	client NodeAttestorClient
}

func (m *GRPCClient) FetchAttestationData(ctx context.Context, req *FetchAttestationDataRequest) (*FetchAttestationDataResponse, error) {
	return m.client.FetchAttestationData(ctx, req)
}

func (m *GRPCClient) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return m.client.Configure(ctx, req)
}

func (m *GRPCClient) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.client.GetPluginInfo(ctx, req)
}
