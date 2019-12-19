// Provides interfaces and adapters for the KeyManager service
//
// Generated code. Do not modify by hand.
package keymanager

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/agent/keymanager"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
)

type FetchPrivateKeyRequest = keymanager.FetchPrivateKeyRequest               //nolint: golint
type FetchPrivateKeyResponse = keymanager.FetchPrivateKeyResponse             //nolint: golint
type GenerateKeyPairRequest = keymanager.GenerateKeyPairRequest               //nolint: golint
type GenerateKeyPairResponse = keymanager.GenerateKeyPairResponse             //nolint: golint
type KeyManagerClient = keymanager.KeyManagerClient                           //nolint: golint
type KeyManagerServer = keymanager.KeyManagerServer                           //nolint: golint
type StorePrivateKeyRequest = keymanager.StorePrivateKeyRequest               //nolint: golint
type StorePrivateKeyResponse = keymanager.StorePrivateKeyResponse             //nolint: golint
type UnimplementedKeyManagerServer = keymanager.UnimplementedKeyManagerServer //nolint: golint

const (
	Type = "KeyManager"
)

// KeyManager is the client interface for the service type KeyManager interface.
type KeyManager interface {
	FetchPrivateKey(context.Context, *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error)
	GenerateKeyPair(context.Context, *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error)
	StorePrivateKey(context.Context, *StorePrivateKeyRequest) (*StorePrivateKeyResponse, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	FetchPrivateKey(context.Context, *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error)
	GenerateKeyPair(context.Context, *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
	StorePrivateKey(context.Context, *StorePrivateKeyRequest) (*StorePrivateKeyResponse, error)
}

// PluginServer returns a catalog PluginServer implementation for the KeyManager plugin.
func PluginServer(server KeyManagerServer) catalog.PluginServer {
	return &pluginServer{
		server: server,
	}
}

type pluginServer struct {
	server KeyManagerServer
}

func (s pluginServer) PluginType() string {
	return Type
}

func (s pluginServer) PluginClient() catalog.PluginClient {
	return PluginClient
}

func (s pluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	keymanager.RegisterKeyManagerServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the KeyManager plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClient(keymanager.NewKeyManagerClient(conn))
}

func AdaptPluginClient(client KeyManagerClient) KeyManager {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client KeyManagerClient
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) FetchPrivateKey(ctx context.Context, in *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error) {
	return a.client.FetchPrivateKey(ctx, in)
}

func (a pluginClientAdapter) GenerateKeyPair(ctx context.Context, in *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error) {
	return a.client.GenerateKeyPair(ctx, in)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}

func (a pluginClientAdapter) StorePrivateKey(ctx context.Context, in *StorePrivateKeyRequest) (*StorePrivateKeyResponse, error) {
	return a.client.StorePrivateKey(ctx, in)
}
