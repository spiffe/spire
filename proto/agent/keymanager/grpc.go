package keymanager

import (
	"golang.org/x/net/context"

	spi "github.com/spiffe/spire/proto/common/plugin"
)

type GRPCClient struct {
	client KeyManagerClient
}

func (m *GRPCClient) GenerateKeyPair(ctx context.Context, req *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	return m.client.GenerateKeyPair(ctx, req)
}

func (m *GRPCClient) FetchPrivateKey(ctx context.Context, req *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	return m.client.FetchPrivateKey(ctx, req)
}

func (m *GRPCClient) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return m.client.Configure(ctx, req)
}

func (m *GRPCClient) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return m.client.GetPluginInfo(ctx, req)
}
