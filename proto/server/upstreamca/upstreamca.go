// Provides interfaces and adapters for the UpstreamCA service
//
// Generated code. Do not modify by hand.
package upstreamca

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog/interfaces"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"google.golang.org/grpc"
)

const (
	Type = "UpstreamCA"
)

// UpstreamCA is the client interface for the service type UpstreamCA interface.
type UpstreamCA interface {
	SubmitCSR(context.Context, *SubmitCSRRequest) (*SubmitCSRResponse, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
	SubmitCSR(context.Context, *SubmitCSRRequest) (*SubmitCSRResponse, error)
}

// PluginServer returns a catalog PluginServer implementation for the UpstreamCA plugin.
func PluginServer(server UpstreamCAServer) interfaces.PluginServer {
	return &pluginServer{
		server: server,
	}
}

type pluginServer struct {
	server UpstreamCAServer
}

func (s pluginServer) PluginType() string {
	return Type
}

func (s pluginServer) PluginClient() interfaces.PluginClient {
	return PluginClient
}

func (s pluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	RegisterUpstreamCAServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the UpstreamCA plugin.
var PluginClient interfaces.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClient(NewUpstreamCAClient(conn))
}

func AdaptPluginClient(client UpstreamCAClient) UpstreamCA {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client UpstreamCAClient
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}

func (a pluginClientAdapter) SubmitCSR(ctx context.Context, in *SubmitCSRRequest) (*SubmitCSRResponse, error) {
	return a.client.SubmitCSR(ctx, in)
}
