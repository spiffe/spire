// Provides interfaces and adapters for the AgentStore service
//
// Generated code. Do not modify by hand.
package agentstorev0

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc"
)

const (
	Type = "AgentStore"
)

// AgentStore is the client interface for the service type AgentStore interface.
type AgentStore interface {
	GetAgentInfo(context.Context, *GetAgentInfoRequest) (*GetAgentInfoResponse, error)
}

// HostServiceServer returns a catalog HostServiceServer implementation for the AgentStore plugin.
func HostServiceServer(server AgentStoreServer) catalog.HostServiceServer {
	return &hostServiceServer{
		server: server,
	}
}

type hostServiceServer struct {
	server AgentStoreServer
}

func (s hostServiceServer) HostServiceType() string {
	return Type
}

func (s hostServiceServer) RegisterHostServiceServer(server *grpc.Server) {
	RegisterAgentStoreServer(server, s.server)
}

// HostServiceServer returns a catalog HostServiceServer implementation for the AgentStore plugin.
func HostServiceClient(client *AgentStore) catalog.HostServiceClient {
	return &hostServiceClient{
		client: client,
	}
}

type hostServiceClient struct {
	client *AgentStore
}

func (c *hostServiceClient) HostServiceType() string {
	return Type
}

func (c *hostServiceClient) InitHostServiceClient(conn grpc.ClientConnInterface) {
	*c.client = AdaptHostServiceClient(NewAgentStoreClient(conn))
}

func AdaptHostServiceClient(client AgentStoreClient) AgentStore {
	return hostServiceClientAdapter{client: client}
}

type hostServiceClientAdapter struct {
	client AgentStoreClient
}

func (a hostServiceClientAdapter) GetAgentInfo(ctx context.Context, in *GetAgentInfoRequest) (*GetAgentInfoResponse, error) {
	return a.client.GetAgentInfo(ctx, in)
}
