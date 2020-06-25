package agent

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
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
	log := rpccontext.Logger(ctx)

	reqID, err := api.IDFromProto(req.Id)
	if err != nil {
		log.WithError(err).Error("Failed to parse SPIFFE ID")
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse SPIFFE ID: %v", err)
	}

	log = log.WithField(telemetry.SPIFFEID, reqID.String())
	resp, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
		SpiffeId: reqID.String(),
	})
	if err != nil {
		log.WithError(err).Error("Failed to fetch node")
		return nil, status.Errorf(codes.Internal, "failed to fetch node: %v", err)
	}

	if resp.Node == nil {
		log.Error("Agent not found")
		return nil, status.Error(codes.NotFound, "agent not found")
	}

	selectors, err := s.getSelectorsFromAgentID(ctx, resp.Node.SpiffeId)
	if err != nil {
		log.WithError(err).Error("Failed to get selectors from attested node")
		return nil, status.Errorf(codes.Internal, "failed to get selectors from attested node: %v", err)
	}

	agent, err := api.AttestedNodeToProto(resp.Node, selectors)
	if err != nil {
		log.WithError(err).Error("Failed to convert from attested node")
		return nil, status.Errorf(codes.Internal, "failed to convert from attested node: %v", err)
	}

	applyMask(agent, req.OutputMask)
	return agent, nil
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

func (s *Service) getSelectorsFromAgentID(ctx context.Context, agentID string) ([]*types.Selector, error) {
	resp, err := s.ds.GetNodeSelectors(ctx, &datastore.GetNodeSelectorsRequest{
		SpiffeId: agentID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get node selectors: %v", err)
	}

	return api.NodeSelectorsToProto(resp.Selectors)
}
