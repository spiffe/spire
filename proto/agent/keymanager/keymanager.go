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
	GenerateKeyPair(context.Context, *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error)
	StorePrivateKey(context.Context, *StorePrivateKeyRequest) (*StorePrivateKeyResponse, error)
	FetchPrivateKey(context.Context, *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error)
}

// Plugin is the interface implemented by plugin implementations
type Plugin interface {
	GenerateKeyPair(context.Context, *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error)
	StorePrivateKey(context.Context, *StorePrivateKeyRequest) (*StorePrivateKeyResponse, error)
	FetchPrivateKey(context.Context, *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error)
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

func (b BuiltIn) GenerateKeyPair(ctx context.Context, req *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	resp, err := b.plugin.GenerateKeyPair(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) StorePrivateKey(ctx context.Context, req *StorePrivateKeyRequest) (*StorePrivateKeyResponse, error) {
	resp, err := b.plugin.StorePrivateKey(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (b BuiltIn) FetchPrivateKey(ctx context.Context, req *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	resp, err := b.plugin.FetchPrivateKey(ctx, req)
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

func (s *GRPCServer) GenerateKeyPair(ctx context.Context, req *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	return s.Plugin.GenerateKeyPair(ctx, req)
}
func (s *GRPCServer) StorePrivateKey(ctx context.Context, req *StorePrivateKeyRequest) (*StorePrivateKeyResponse, error) {
	return s.Plugin.StorePrivateKey(ctx, req)
}
func (s *GRPCServer) FetchPrivateKey(ctx context.Context, req *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	return s.Plugin.FetchPrivateKey(ctx, req)
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

func (c *GRPCClient) GenerateKeyPair(ctx context.Context, req *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	return c.client.GenerateKeyPair(ctx, req)
}
func (c *GRPCClient) StorePrivateKey(ctx context.Context, req *StorePrivateKeyRequest) (*StorePrivateKeyResponse, error) {
	return c.client.StorePrivateKey(ctx, req)
}
func (c *GRPCClient) FetchPrivateKey(ctx context.Context, req *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	return c.client.FetchPrivateKey(ctx, req)
}
func (c *GRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *GRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
