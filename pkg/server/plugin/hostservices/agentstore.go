// Provides interfaces and adapters for the AgentStore service
//
// Generated code. Do not modify by hand.
package hostservices

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/server/hostservices"
	"google.golang.org/grpc"
)

type AgentInfo = hostservices.AgentInfo                                         //nolint: golint
type AgentStoreClient = hostservices.AgentStoreClient                           //nolint: golint
type AgentStoreServer = hostservices.AgentStoreServer                           //nolint: golint
type GetAgentInfoRequest = hostservices.GetAgentInfoRequest                     //nolint: golint
type GetAgentInfoResponse = hostservices.GetAgentInfoResponse                   //nolint: golint
type UnimplementedAgentStoreServer = hostservices.UnimplementedAgentStoreServer //nolint: golint
type UnsafeAgentStoreServer = hostservices.UnsafeAgentStoreServer               //nolint: golint

const (
	AgentStoreType = "AgentStore"
)

// AgentStore is the client interface for the service type AgentStore interface.
type AgentStore interface {
	GetAgentInfo(context.Context, *GetAgentInfoRequest) (*GetAgentInfoResponse, error)
}

// AgentStoreHostServiceServer returns a catalog HostServiceServer implementation for the AgentStore plugin.
func AgentStoreHostServiceServer(server AgentStoreServer) catalog.HostServiceServer {
	return &agentStoreHostServiceServer{
		server: server,
	}
}

type agentStoreHostServiceServer struct {
	server AgentStoreServer
}

func (s agentStoreHostServiceServer) HostServiceType() string {
	return AgentStoreType
}

func (s agentStoreHostServiceServer) RegisterHostServiceServer(server *grpc.Server) {
	hostservices.RegisterAgentStoreServer(server, s.server)
}

// AgentStoreHostServiceServer returns a catalog HostServiceServer implementation for the AgentStore plugin.
func AgentStoreHostServiceClient(client *AgentStore) catalog.HostServiceClient {
	return &agentStoreHostServiceClient{
		client: client,
	}
}

type agentStoreHostServiceClient struct {
	client *AgentStore
}

func (c *agentStoreHostServiceClient) HostServiceType() string {
	return AgentStoreType
}

func (c *agentStoreHostServiceClient) InitHostServiceClient(conn grpc.ClientConnInterface) {
	*c.client = AdaptAgentStoreHostServiceClient(hostservices.NewAgentStoreClient(conn))
}

func AdaptAgentStoreHostServiceClient(client AgentStoreClient) AgentStore {
	return agentStoreHostServiceClientAdapter{client: client}
}

type agentStoreHostServiceClientAdapter struct {
	client AgentStoreClient
}

func (a agentStoreHostServiceClientAdapter) GetAgentInfo(ctx context.Context, in *GetAgentInfoRequest) (*GetAgentInfoResponse, error) {
	return a.client.GetAgentInfo(ctx, in)
}
