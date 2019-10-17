// Provides interfaces and adapters for the WorkloadAttestor service
//
// Generated code. Do not modify by hand.
package workloadattestor

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc"
)

const (
	Type = "WorkloadAttestor"
)

// WorkloadAttestor is the client interface for the service type WorkloadAttestor interface.
type WorkloadAttestor interface {
	Attest(context.Context, *AttestRequest) (*AttestResponse, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Attest(context.Context, *AttestRequest) (*AttestResponse, error)
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
}

// PluginServer returns a catalog PluginServer implementation for the WorkloadAttestor plugin.
func PluginServer(server WorkloadAttestorServer) catalog.PluginServer {
	return &pluginServer{
		server: server,
	}
}

type pluginServer struct {
	server WorkloadAttestorServer
}

func (s pluginServer) PluginType() string {
	return Type
}

func (s pluginServer) PluginClient() catalog.PluginClient {
	return PluginClient
}

func (s pluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	RegisterWorkloadAttestorServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the WorkloadAttestor plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClient(NewWorkloadAttestorClient(conn))
}

func AdaptPluginClient(client WorkloadAttestorClient) WorkloadAttestor {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client WorkloadAttestorClient
}

func (a pluginClientAdapter) Attest(ctx context.Context, in *AttestRequest) (*AttestResponse, error) {
	return a.client.Attest(ctx, in)
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}
