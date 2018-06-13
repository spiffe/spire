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
	FetchPrivateKey(context.Context, *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error)
}

// KeyManager is the interface implemented by plugin implementations
type KeyManagerPlugin interface {
	GenerateKeyPair(context.Context, *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error)
	FetchPrivateKey(context.Context, *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error)
	Configure(context.Context, *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error)
	GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error)
}

type KeyManagerBuiltIn struct {
	plugin KeyManagerPlugin
}

var _ KeyManager = (*KeyManagerBuiltIn)(nil)

func NewKeyManagerBuiltIn(plugin KeyManagerPlugin) *KeyManagerBuiltIn {
	return &KeyManagerBuiltIn{
		plugin: plugin,
	}
}

func (b KeyManagerBuiltIn) GenerateKeyPair(ctx context.Context, req *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	return b.plugin.GenerateKeyPair(ctx, req)
}

func (b KeyManagerBuiltIn) FetchPrivateKey(ctx context.Context, req *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	return b.plugin.FetchPrivateKey(ctx, req)
}

func (b KeyManagerBuiltIn) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return b.plugin.Configure(ctx, req)
}

func (b KeyManagerBuiltIn) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return b.plugin.GetPluginInfo(ctx, req)
}

var Handshake = go_plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "KeyManager",
	MagicCookieValue: "KeyManager",
}

type KeyManagerGRPCPlugin struct {
	ServerImpl KeyManagerServer
}

func (p KeyManagerGRPCPlugin) Server(*go_plugin.MuxBroker) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p KeyManagerGRPCPlugin) Client(b *go_plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return empty.Empty{}, nil
}

func (p KeyManagerGRPCPlugin) GRPCServer(s *grpc.Server) error {
	RegisterKeyManagerServer(s, p.ServerImpl)
	return nil
}

func (p KeyManagerGRPCPlugin) GRPCClient(c *grpc.ClientConn) (interface{}, error) {
	return &KeyManagerGRPCClient{client: NewKeyManagerClient(c)}, nil
}

type KeyManagerGRPCServer struct {
	Plugin KeyManagerPlugin
}

func (s *KeyManagerGRPCServer) GenerateKeyPair(ctx context.Context, req *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	return s.Plugin.GenerateKeyPair(ctx, req)
}
func (s *KeyManagerGRPCServer) FetchPrivateKey(ctx context.Context, req *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	return s.Plugin.FetchPrivateKey(ctx, req)
}
func (s *KeyManagerGRPCServer) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return s.Plugin.Configure(ctx, req)
}
func (s *KeyManagerGRPCServer) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return s.Plugin.GetPluginInfo(ctx, req)
}

type KeyManagerGRPCClient struct {
	client KeyManagerClient
}

func (c *KeyManagerGRPCClient) GenerateKeyPair(ctx context.Context, req *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	return c.client.GenerateKeyPair(ctx, req)
}
func (c *KeyManagerGRPCClient) FetchPrivateKey(ctx context.Context, req *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	return c.client.FetchPrivateKey(ctx, req)
}
func (c *KeyManagerGRPCClient) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	return c.client.Configure(ctx, req)
}
func (c *KeyManagerGRPCClient) GetPluginInfo(ctx context.Context, req *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return c.client.GetPluginInfo(ctx, req)
}
