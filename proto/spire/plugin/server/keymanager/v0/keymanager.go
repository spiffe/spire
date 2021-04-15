// Provides interfaces and adapters for the KeyManager service
//
// Generated code. Do not modify by hand.
package keymanagerv0

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
)

const (
	Type = "KeyManager"
)

// KeyManager is the client interface for the service type KeyManager interface.
type KeyManager interface {
	GenerateKey(context.Context, *GenerateKeyRequest) (*GenerateKeyResponse, error)
	GetPublicKey(context.Context, *GetPublicKeyRequest) (*GetPublicKeyResponse, error)
	GetPublicKeys(context.Context, *GetPublicKeysRequest) (*GetPublicKeysResponse, error)
	SignData(context.Context, *SignDataRequest) (*SignDataResponse, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GenerateKey(context.Context, *GenerateKeyRequest) (*GenerateKeyResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
	GetPublicKey(context.Context, *GetPublicKeyRequest) (*GetPublicKeyResponse, error)
	GetPublicKeys(context.Context, *GetPublicKeysRequest) (*GetPublicKeysResponse, error)
	SignData(context.Context, *SignDataRequest) (*SignDataResponse, error)
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
	RegisterKeyManagerServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the KeyManager plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn grpc.ClientConnInterface) interface{} {
	return AdaptPluginClient(NewKeyManagerClient(conn))
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

func (a pluginClientAdapter) GenerateKey(ctx context.Context, in *GenerateKeyRequest) (*GenerateKeyResponse, error) {
	return a.client.GenerateKey(ctx, in)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}

func (a pluginClientAdapter) GetPublicKey(ctx context.Context, in *GetPublicKeyRequest) (*GetPublicKeyResponse, error) {
	return a.client.GetPublicKey(ctx, in)
}

func (a pluginClientAdapter) GetPublicKeys(ctx context.Context, in *GetPublicKeysRequest) (*GetPublicKeysResponse, error) {
	return a.client.GetPublicKeys(ctx, in)
}

func (a pluginClientAdapter) SignData(ctx context.Context, in *SignDataRequest) (*SignDataResponse, error) {
	return a.client.SignData(ctx, in)
}
