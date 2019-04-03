// Provides interfaces and adapters for the NodeResolver service
//
// Generated code. Do not modify by hand.
package noderesolver

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog/interfaces"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

const (
	Type = "NodeResolver"
)

// NodeResolver is the client interface for the service type NodeResolver interface.
type NodeResolver interface {
	Resolve(context.Context, *ResolveRequest) (*ResolveResponse, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
	Resolve(context.Context, *ResolveRequest) (*ResolveResponse, error)
}

// PluginServer returns a catalog PluginServer implementation for the NodeResolver plugin.
func PluginServer(server NodeResolverServer) interfaces.PluginServer {
	return &pluginServer{
		server: server,
	}
}

type pluginServer struct {
	server NodeResolverServer
}

func (s pluginServer) PluginType() string {
	return Type
}

func (s pluginServer) PluginClient() interfaces.PluginClient {
	return PluginClient
}

func (s pluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	RegisterNodeResolverServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the NodeResolver plugin.
var PluginClient interfaces.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClient(NewNodeResolverClient(conn))
}

func AdaptPluginClient(client NodeResolverClient) NodeResolver {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client NodeResolverClient
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}

func (a pluginClientAdapter) Resolve(ctx context.Context, in *ResolveRequest) (*ResolveResponse, error) {
	return a.client.Resolve(ctx, in)
}
