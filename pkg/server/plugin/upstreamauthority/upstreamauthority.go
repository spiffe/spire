// Provides interfaces and adapters for the UpstreamAuthority service
//
// Generated code. Do not modify by hand.
package upstreamauthority

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/upstreamauthority"
	"google.golang.org/grpc"
)

type MintX509CARequest = upstreamauthority.MintX509CARequest                                       //nolint: golint
type MintX509CAResponse = upstreamauthority.MintX509CAResponse                                     //nolint: golint
type PublishJWTKeyRequest = upstreamauthority.PublishJWTKeyRequest                                 //nolint: golint
type PublishJWTKeyResponse = upstreamauthority.PublishJWTKeyResponse                               //nolint: golint
type UnimplementedUpstreamAuthorityServer = upstreamauthority.UnimplementedUpstreamAuthorityServer //nolint: golint
type UpstreamAuthorityClient = upstreamauthority.UpstreamAuthorityClient                           //nolint: golint
type UpstreamAuthorityServer = upstreamauthority.UpstreamAuthorityServer                           //nolint: golint

const (
	Type = "UpstreamAuthority"
)

// UpstreamAuthority is the client interface for the service type UpstreamAuthority interface.
type UpstreamAuthority interface {
	MintX509CA(context.Context, *MintX509CARequest) (*MintX509CAResponse, error)
	PublishJWTKey(context.Context, *PublishJWTKeyRequest) (*PublishJWTKeyResponse, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
	MintX509CA(context.Context, *MintX509CARequest) (*MintX509CAResponse, error)
	PublishJWTKey(context.Context, *PublishJWTKeyRequest) (*PublishJWTKeyResponse, error)
}

// PluginServer returns a catalog PluginServer implementation for the UpstreamAuthority plugin.
func PluginServer(server UpstreamAuthorityServer) catalog.PluginServer {
	return &pluginServer{
		server: server,
	}
}

type pluginServer struct {
	server UpstreamAuthorityServer
}

func (s pluginServer) PluginType() string {
	return Type
}

func (s pluginServer) PluginClient() catalog.PluginClient {
	return PluginClient
}

func (s pluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	upstreamauthority.RegisterUpstreamAuthorityServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the UpstreamAuthority plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClient(upstreamauthority.NewUpstreamAuthorityClient(conn))
}

func AdaptPluginClient(client UpstreamAuthorityClient) UpstreamAuthority {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client UpstreamAuthorityClient
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}

func (a pluginClientAdapter) MintX509CA(ctx context.Context, in *MintX509CARequest) (*MintX509CAResponse, error) {
	return a.client.MintX509CA(ctx, in)
}

func (a pluginClientAdapter) PublishJWTKey(ctx context.Context, in *PublishJWTKeyRequest) (*PublishJWTKeyResponse, error) {
	return a.client.PublishJWTKey(ctx, in)
}
