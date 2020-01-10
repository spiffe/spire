// Provides interfaces and adapters for the NodeAttestor service
//
// Generated code. Do not modify by hand.
package nodeattestor

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
	"google.golang.org/grpc"
)

type AttestRequest = nodeattestor.AttestRequest                                     //nolint: golint
type AttestResponse = nodeattestor.AttestResponse                                   //nolint: golint
type NodeAttestorClient = nodeattestor.NodeAttestorClient                           //nolint: golint
type NodeAttestorServer = nodeattestor.NodeAttestorServer                           //nolint: golint
type NodeAttestor_AttestClient = nodeattestor.NodeAttestor_AttestClient             //nolint: golint
type NodeAttestor_AttestServer = nodeattestor.NodeAttestor_AttestServer             //nolint: golint
type UnimplementedNodeAttestorServer = nodeattestor.UnimplementedNodeAttestorServer //nolint: golint

const (
	Type = "NodeAttestor"
)

// NodeAttestor is the client interface for the service type NodeAttestor interface.
type NodeAttestor interface {
	Attest(context.Context) (NodeAttestor_AttestClient, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Attest(context.Context) (NodeAttestor_AttestClient, error)
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
}

// PluginServer returns a catalog PluginServer implementation for the NodeAttestor plugin.
func PluginServer(server NodeAttestorServer) catalog.PluginServer {
	return &pluginServer{
		server: server,
	}
}

type pluginServer struct {
	server NodeAttestorServer
}

func (s pluginServer) PluginType() string {
	return Type
}

func (s pluginServer) PluginClient() catalog.PluginClient {
	return PluginClient
}

func (s pluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	nodeattestor.RegisterNodeAttestorServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the NodeAttestor plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClient(nodeattestor.NewNodeAttestorClient(conn))
}

func AdaptPluginClient(client NodeAttestorClient) NodeAttestor {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client NodeAttestorClient
}

func (a pluginClientAdapter) Attest(ctx context.Context) (NodeAttestor_AttestClient, error) {
	return a.client.Attest(ctx)
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}
