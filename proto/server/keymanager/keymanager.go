package keymanager

import (
	"context"
	"net/rpc"

	"github.com/golang/protobuf/ptypes/empty"
	go_plugin "github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

// KeyManager is the interface used by all non-catalog components.
type KeyManager interface {
	GenerateKey(context.Context, *GenerateKeyRequest) (*GenerateKeyResponse, error)
	GetPublicKey(context.Context, *GetPublicKeyRequest) (*GetPublicKeyResponse, error)
	GetPublicKeys(context.Context, *GetPublicKeysRequest) (*GetPublicKeysResponse, error)
	SignData(context.Context, *SignDataRequest) (*SignDataResponse, error)
}

// Plugin is the interface implemented by plugin implementations
type Plugin interface {
	GenerateKey(context.Context, *GenerateKeyRequest) (*GenerateKeyResponse, error)
	GetPublicKey(context.Context, *GetPublicKeyRequest) (*GetPublicKeyResponse, error)
	GetPublicKeys(context.Context, *GetPublicKeysRequest) (*GetPublicKeysResponse, error)
	SignData(context.Context, *SignDataRequest) (*SignDataResponse, error)
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type BuiltIn struct {
	plugin Plugin
}

var _ KeyManager = (*BuiltIn)(nil)

func NewBuiltIn(plugin Plugin) *BuiltIn {
	return &BuiltIn{
		plugin: plugin,
	}
}

func (b BuiltIn) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	resp, err := b.plugin.GenerateKey(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) GetPublicKey(ctx context.Context, req *GetPublicKeyRequest) (*GetPublicKeyResponse, error) {
	resp, err := b.plugin.GetPublicKey(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) GetPublicKeys(ctx context.Context, req *GetPublicKeysRequest) (*GetPublicKeysResponse, error) {
	resp, err := b.plugin.GetPublicKeys(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) SignData(ctx context.Context, req *SignDataRequest) (*SignDataResponse, error) {
	resp, err := b.plugin.SignData(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	resp, err := b.plugin.Configure(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	resp, err := b.plugin.GetPluginInfo(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "KeyManager",
	MagicCookieValue: "KeyManager",
}

type GRPCPlugin struct {
	ServerImpl KeyManagerServer
}

var _ go_plugin.GRPCPlugin = (*GRPCPlugin)(nil)

func (p GRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p GRPCPlugin) GRPCServer(b *go_plugin.GRPCBroker, s *grpc.Server) error {
	RegisterKeyManagerServer(s, p.ServerImpl)
	return nil
}

func (p GRPCPlugin) GRPCClient(ctx context.Context, b *go_plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewKeyManagerClient(c)}, nil
}

type GRPCServer struct {
	Plugin Plugin
}

func (s *GRPCServer) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	return s.Plugin.GenerateKey(ctx, req)
}
func (s *GRPCServer) GetPublicKey(ctx context.Context, req *GetPublicKeyRequest) (*GetPublicKeyResponse, error) {
	return s.Plugin.GetPublicKey(ctx, req)
}
func (s *GRPCServer) GetPublicKeys(ctx context.Context, req *GetPublicKeysRequest) (*GetPublicKeysResponse, error) {
	return s.Plugin.GetPublicKeys(ctx, req)
}
func (s *GRPCServer) SignData(ctx context.Context, req *SignDataRequest) (*SignDataResponse, error) {
	return s.Plugin.SignData(ctx, req)
}
func (s *GRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *GRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type GRPCClient struct {
	client KeyManagerClient
}

func (c *GRPCClient) GenerateKey(ctx context.Context, req *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	return c.client.GenerateKey(ctx, req)
}
func (c *GRPCClient) GetPublicKey(ctx context.Context, req *GetPublicKeyRequest) (*GetPublicKeyResponse, error) {
	return c.client.GetPublicKey(ctx, req)
}
func (c *GRPCClient) GetPublicKeys(ctx context.Context, req *GetPublicKeysRequest) (*GetPublicKeysResponse, error) {
	return c.client.GetPublicKeys(ctx, req)
}
func (c *GRPCClient) SignData(ctx context.Context, req *SignDataRequest) (*SignDataResponse, error) {
	return c.client.SignData(ctx, req)
}
func (c *GRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *GRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
