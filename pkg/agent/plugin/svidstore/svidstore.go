// Provides interfaces and adapters for the SVIDStore service
//
// Generated code. Do not modify by hand.
package svidstore

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/agent/svidstore"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
)

type PutX509SVIDRequest = svidstore.PutX509SVIDRequest                     //nolint: golint
type PutX509SVIDResponse = svidstore.PutX509SVIDResponse                   //nolint: golint
type SVIDStoreClient = svidstore.SVIDStoreClient                           //nolint: golint
type SVIDStoreServer = svidstore.SVIDStoreServer                           //nolint: golint
type UnimplementedSVIDStoreServer = svidstore.UnimplementedSVIDStoreServer //nolint: golint
type UnsafeSVIDStoreServer = svidstore.UnsafeSVIDStoreServer               //nolint: golint
type X509SVID = svidstore.X509SVID                                         //nolint: golint

const (
	Type = "SVIDStore"
)

// SVIDStore is the client interface for the service type SVIDStore interface.
type SVIDStore interface {
	PutX509SVID(context.Context, *PutX509SVIDRequest) (*PutX509SVIDResponse, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
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
	svidstore.RegisterSVIDStoreServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the SVIDStore plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn grpc.ClientConnInterface) interface{} {
	return AdaptPluginClient(svidstore.NewSVIDStoreClient(conn))
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

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}

func (a pluginClientAdapter) PutX509SVID(ctx context.Context, in *PutX509SVIDRequest) (*PutX509SVIDResponse, error) {
	return a.client.PutX509SVID(ctx, in)
}
