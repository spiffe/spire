// Provides interfaces and adapters for the Notifier service
//
// Generated code. Do not modify by hand.
package notifier

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
)

const (
	Type = "Notifier"
)

// Notifier is the client interface for the service type Notifier interface.
type Notifier interface {
	Notify(context.Context, *NotifyRequest) (*NotifyResponse, error)
	NotifyAndAdvise(context.Context, *NotifyAndAdviseRequest) (*NotifyAndAdviseResponse, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
	Notify(context.Context, *NotifyRequest) (*NotifyResponse, error)
	NotifyAndAdvise(context.Context, *NotifyAndAdviseRequest) (*NotifyAndAdviseResponse, error)
}

// PluginServer returns a catalog PluginServer implementation for the Notifier plugin.
func PluginServer(server NotifierServer) catalog.PluginServer {
	return &pluginServer{
		server: server,
	}
}

type pluginServer struct {
	server NotifierServer
}

func (s pluginServer) PluginType() string {
	return Type
}

func (s pluginServer) PluginClient() catalog.PluginClient {
	return PluginClient
}

func (s pluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	RegisterNotifierServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the Notifier plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClient(NewNotifierClient(conn))
}

func AdaptPluginClient(client NotifierClient) Notifier {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client NotifierClient
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}

func (a pluginClientAdapter) Notify(ctx context.Context, in *NotifyRequest) (*NotifyResponse, error) {
	return a.client.Notify(ctx, in)
}

func (a pluginClientAdapter) NotifyAndAdvise(ctx context.Context, in *NotifyAndAdviseRequest) (*NotifyAndAdviseResponse, error) {
	return a.client.NotifyAndAdvise(ctx, in)
}
