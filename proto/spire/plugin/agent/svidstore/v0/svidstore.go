// Provides interfaces and adapters for the SVIDStore service
//
// Generated code. Do not modify by hand.
package svidstorev0

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
)

const (
	Type = "SVIDStore"
)

// SVIDStore is the client interface for the service type SVIDStore interface.
type SVIDStore interface {
	DeleteX509SVID(context.Context, *DeleteX509SVIDRequest) (*DeleteX509SVIDResponse, error)
	PutX509SVID(context.Context, *PutX509SVIDRequest) (*PutX509SVIDResponse, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	DeleteX509SVID(context.Context, *DeleteX509SVIDRequest) (*DeleteX509SVIDResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
	PutX509SVID(context.Context, *PutX509SVIDRequest) (*PutX509SVIDResponse, error)
}

// PluginServer returns a catalog PluginServer implementation for the SVIDStore plugin.
func PluginServer(server SVIDStoreServer) catalog.PluginServer {
	return &pluginServer{
		server: server,
	}
}

type pluginServer struct {
	server SVIDStoreServer
}

func (s pluginServer) PluginType() string {
	return Type
}

func (s pluginServer) PluginClient() catalog.PluginClient {
	return PluginClient
}

func (s pluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	RegisterSVIDStoreServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the SVIDStore plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn grpc.ClientConnInterface) interface{} {
	return AdaptPluginClient(NewSVIDStoreClient(conn))
}

func AdaptPluginClient(client SVIDStoreClient) SVIDStore {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client SVIDStoreClient
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) DeleteX509SVID(ctx context.Context, in *DeleteX509SVIDRequest) (*DeleteX509SVIDResponse, error) {
	return a.client.DeleteX509SVID(ctx, in)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}

func (a pluginClientAdapter) PutX509SVID(ctx context.Context, in *PutX509SVIDRequest) (*PutX509SVIDResponse, error) {
	return a.client.PutX509SVID(ctx, in)
}
