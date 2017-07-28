package keymanager

import (
	"github.com/spiffe/node-agent/plugins/key_manager/proto"
	"golang.org/x/net/context"
)

type GRPCServer struct {
	KeyManagerImpl KeyManager
}

func (m *GRPCServer) GenerateKeyPair(ctx context.Context, req *proto.GenerateKeyPairRequest) (*proto.GenerateKeyPairResponse, error) {
	response, err := m.KeyManagerImpl.GenerateKeyPair()
	return &proto.GenerateKeyPairResponse{PublicKey: response}, err
}

func (m *GRPCServer) Configure(ctx context.Context, req *proto.ConfigureRequest) (*proto.Empty, error) {
	err := m.KeyManagerImpl.Configure(req.Configuration)
	return &proto.Empty{}, err
}

type GRPCClient struct {
	client proto.KeyManagerClient
}

func (m *GRPCClient) GenerateKeyPair() ([]byte, error) {
	res, err := m.client.GenerateKeyPair(context.Background(), &proto.GenerateKeyPairRequest{})
	if err != nil {
		return []byte{}, err
	}
	return res.PublicKey, err
}

func (m *GRPCClient) Configure(configuration string) error {
	_, err := m.client.Configure(context.Background(), &proto.ConfigureRequest{
		Configuration: configuration,
	})
	return err
}
