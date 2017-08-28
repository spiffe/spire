package keymanager

import (
	"github.com/spiffe/sri/pkg/common/plugin"
	"golang.org/x/net/context"
)

type grpcServer struct {
	delegate Interface
}

func (m *grpcServer) GenerateKeyPair(ctx context.Context, req *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	response, err := m.delegate.GenerateKeyPair(req)
	return response, err
}

func (m *grpcServer) FetchPrivateKey(ctx context.Context, req *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	response, err := m.delegate.FetchPrivateKey(req)
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
	client KeyManagerClient
}

func (m *grpcClient) GenerateKeyPair(req *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	res, err := m.client.GenerateKeyPair(context.Background(), req)
	return res, err
}

func (m *grpcClient) FetchPrivateKey(req *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	res, err := m.client.FetchPrivateKey(context.Background(), req)
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
