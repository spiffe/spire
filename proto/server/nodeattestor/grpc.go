package nodeattestor

import (
	"golang.org/x/net/context"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

type GRPCClient struct {
	client NodeAttestorClient
}

func (m *GRPCClient) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return m.client.Configure(ctx, req)
}

func (m *GRPCClient) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.client.GetPluginInfo(ctx, req)
}

func (m *GRPCClient) Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error) {
	return m.client.Attest(ctx, req)
}
