// Provides interfaces and adapters for the NodeAttestor service
//
// Generated code. Do not modify by hand.
package nodeattestor

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
)

type FetchAttestationDataRequest = nodeattestor.FetchAttestationDataRequest                         //nolint: golint
type FetchAttestationDataResponse = nodeattestor.FetchAttestationDataResponse                       //nolint: golint
type NodeAttestorClient = nodeattestor.NodeAttestorClient                                           //nolint: golint
type NodeAttestorServer = nodeattestor.NodeAttestorServer                                           //nolint: golint
type NodeAttestor_FetchAttestationDataClient = nodeattestor.NodeAttestor_FetchAttestationDataClient //nolint: golint
type NodeAttestor_FetchAttestationDataServer = nodeattestor.NodeAttestor_FetchAttestationDataServer //nolint: golint
type UnimplementedNodeAttestorServer = nodeattestor.UnimplementedNodeAttestorServer                 //nolint: golint
type UnsafeNodeAttestorServer = nodeattestor.UnsafeNodeAttestorServer                               //nolint: golint

const (
	Type = "NodeAttestor"
)

// NodeAttestor is the client interface for the service type NodeAttestor interface.
type NodeAttestor interface {
	FetchAttestationData(context.Context) (NodeAttestor_FetchAttestationDataClient, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	FetchAttestationData(context.Context) (NodeAttestor_FetchAttestationDataClient, error)
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

func (pluginClient) NewPluginClient(conn grpc.ClientConnInterface) interface{} {
	return AdaptPluginClient(nodeattestor.NewNodeAttestorClient(conn))
}

func AdaptPluginClient(client NodeAttestorClient) NodeAttestor {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client NodeAttestorClient
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) FetchAttestationData(ctx context.Context) (NodeAttestor_FetchAttestationDataClient, error) {
	return a.client.FetchAttestationData(ctx)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}
