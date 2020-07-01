// Provides interfaces and adapters for the Plugin service
//
// Generated code. Do not modify by hand.
package catalogtest

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
)

const (
	PluginType = "Plugin"
)

// Plugin is the client interface for the service type Plugin interface.
type Plugin interface {
	CallPlugin(context.Context, *Request) (*Response, error)
}

// PluginPlugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type PluginPlugin interface {
	CallPlugin(context.Context, *Request) (*Response, error)
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
}

// PluginPluginServer returns a catalog PluginServer implementation for the Plugin plugin.
func PluginPluginServer(server PluginServer) catalog.PluginServer {
	return &pluginPluginServer{
		server: server,
	}
}

type pluginPluginServer struct {
	server PluginServer
}

func (s pluginPluginServer) PluginType() string {
	return PluginType
}

func (s pluginPluginServer) PluginClient() catalog.PluginClient {
	return PluginPluginClient
}

func (s pluginPluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	RegisterPluginServer(server, s.server)
	return s.server
}

// PluginPluginClient is a catalog PluginClient implementation for the Plugin plugin.
var PluginPluginClient catalog.PluginClient = pluginPluginClient{}

type pluginPluginClient struct{}

func (pluginPluginClient) PluginType() string {
	return PluginType
}

func (pluginPluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginPluginClient(NewPluginClient(conn))
}

func AdaptPluginPluginClient(client PluginClient) Plugin {
	return pluginPluginClientAdapter{client: client}
}

type pluginPluginClientAdapter struct {
	client PluginClient
}

func (a pluginPluginClientAdapter) CallPlugin(ctx context.Context, in *Request) (*Response, error) {
	return a.client.CallPlugin(ctx, in)
}

func (a pluginPluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}
