// Provides interfaces and adapters for the AgentStore service
//
// Generated code. Do not modify by hand.
package hostservices

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	agentstorev0 "github.com/spiffe/spire/proto/spire/hostservice/server/agentstore/v0"
	"google.golang.org/grpc"
)

type AgentInfo = agentstorev0.AgentInfo                                         //nolint: golint
type AgentStoreClient = agentstorev0.AgentStoreClient                           //nolint: golint
type AgentStoreServer = agentstorev0.AgentStoreServer                           //nolint: golint
type GetAgentInfoRequest = agentstorev0.GetAgentInfoRequest                     //nolint: golint
type GetAgentInfoResponse = agentstorev0.GetAgentInfoResponse                   //nolint: golint
type UnimplementedAgentStoreServer = agentstorev0.UnimplementedAgentStoreServer //nolint: golint
type UnsafeAgentStoreServer = agentstorev0.UnsafeAgentStoreServer               //nolint: golint

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
	agentstorev0.RegisterAgentStoreServer(server, s.server)
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
	*c.client = AdaptAgentStoreHostServiceClient(agentstorev0.NewAgentStoreClient(conn))
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
