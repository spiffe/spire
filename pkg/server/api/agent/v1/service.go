package agent

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
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
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
		SpiffeId: reqID.String(),
	})
	if err != nil {
		log.Errorf("Failed to fetch node: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to fetch node: %v", err)
	}

	if (resp.Node) == nil {
		log.Error("Agent not found")
		return nil, status.Error(codes.NotFound, "agent not found")
	}

	selectors, err := s.getSelectorsFromAttestedNode(ctx, resp.Node)
	if err != nil {
		log.Errorf("Failed to get selectors from attested node: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to get selectors from attested node: %v", err)
	}

	spiffeID, err := spiffeid.FromString(resp.Node.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("node has malformed SPIFFE ID: %v", err)
	}

	agent := &types.Agent{
		Id:                   api.ProtoFromID(spiffeID),
		AttestationType:      resp.Node.AttestationDataType,
		X509SvidSerialNumber: resp.Node.CertSerialNumber,
		X509SvidExpiresAt:    resp.Node.CertNotAfter,
		Selectors:            selectors,
		Banned:               resp.Node.CertSerialNumber == "" && resp.Node.NewCertSerialNumber == "",
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

func (s *Service) getSelectorsFromAttestedNode(ctx context.Context, node *common.AttestedNode) ([]*types.Selector, error) {
	getNodeSelectorsResponse, err := s.ds.GetNodeSelectors(ctx, &datastore.GetNodeSelectorsRequest{
		SpiffeId: node.SpiffeId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get node selectors: %v", err)
	}

	var selectors []*types.Selector
	for _, s := range getNodeSelectorsResponse.Selectors.Selectors {
		selectors = append(selectors, &types.Selector{
			Type:  s.Type,
			Value: s.Value,
		})
	}

	return selectors, nil
}
