package keymanager

import (
	"github.com/spiffe/sri/pkg/common/plugin"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	KeyManagerImpl KeyManager
}

func (m *GRPCServer) GenerateKeyPair(ctx context.Context, req *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	response, err := m.KeyManagerImpl.GenerateKeyPair(req)
	return response, err
}

func (m *GRPCServer) FetchPrivateKey(ctx context.Context, req *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	response, err := m.KeyManagerImpl.FetchPrivateKey(req)
	return response, err
}

func (m *GRPCServer) Configure(ctx context.Context, req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	response, err := m.KeyManagerImpl.Configure(req)
	return response, err
}

func (m *GRPCServer) GetPluginInfo(ctx context.Context, req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	response, err := m.KeyManagerImpl.GetPluginInfo(req)
	return response, err
}

type GRPCClient struct {
	client KeyManagerClient
}

func (m *GRPCClient) GenerateKeyPair(req *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	res, err := m.client.GenerateKeyPair(context.Background(), req)
	return res, err
}

func (m *GRPCClient) FetchPrivateKey(req *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	res, err := m.client.FetchPrivateKey(context.Background(), req)
	return res, err
}

func (m *GRPCClient) Configure(req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	res, err := m.client.Configure(context.Background(), req)
	return res, err
}

func (m *GRPCClient) GetPluginInfo(req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	res, err := m.client.GetPluginInfo(context.Background(), req)
	return res, err
}
