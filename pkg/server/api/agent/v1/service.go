package agent

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the agent service on the gRPC server/
func RegisterService(s *grpc.Server, service *Service) {
	agent.RegisterAgentServer(s, service)
}

// Config is the service configuration
type Config struct {
	Datastore datastore.DataStore
}

// New creates a new agent service
func New(config Config) *Service {
	return &Service{
		ds: config.Datastore,
	}
}

// Service implements the v1 agent service
type Service struct {
	ds datastore.DataStore
}

func (s *Service) ListAgents(ctx context.Context, req *agent.ListAgentsRequest) (*agent.ListAgentsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

func (s *Service) GetAgent(ctx context.Context, req *agent.GetAgentRequest) (*types.Agent, error) {
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

func (s *Service) DeleteAgent(ctx context.Context, req *agent.DeleteAgentRequest) (*empty.Empty, error) {
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

func (s *Service) BanAgent(ctx context.Context, req *agent.BanAgentRequest) (*empty.Empty, error) {
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

func (s *Service) AttestAgent(stream agent.Agent_AttestAgentServer) error {
	return status.Error(codes.Unimplemented, "method not implemented")
}

func (s *Service) RenewAgent(stream agent.Agent_RenewAgentServer) error {
	return status.Error(codes.Unimplemented, "method not implemented")
}

func (s *Service) CreateJoinToken(ctx context.Context, req *agent.CreateJoinTokenRequest) (*types.JoinToken, error) {
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

func applyMask(a *types.Agent, mask *types.AgentMask) { //nolint: unused,deadcode
	if mask == nil {
		return
	}
	if !mask.AttestationType {
		a.AttestationType = ""
	}

	if !mask.X509SvidSerialNumber {
		a.X509SvidSerialNumber = ""
	}

	if !mask.X509SvidExpiresAt {
		a.X509SvidExpiresAt = 0
	}

	if !mask.Selectors {
		a.Selectors = nil
	}

	if !mask.Banned {
		a.Banned = false
	}
}
