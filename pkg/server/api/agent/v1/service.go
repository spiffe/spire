package agent

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
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
	DataStore   datastore.DataStore
	Datastore   datastore.DataStore
	TrustDomain spiffeid.TrustDomain
}

// New creates a new agent service
func New(config Config) *Service {
	return &Service{
		ds: config.DataStore,
		td: config.TrustDomain,
	}
}

// Service implements the v1 agent service
type Service struct {
	ds datastore.DataStore
	td spiffeid.TrustDomain
}

func (s *Service) ListAgents(ctx context.Context, req *agent.ListAgentsRequest) (*agent.ListAgentsResponse, error) {
	log := rpccontext.Logger(ctx)

	listReq := &datastore.ListAttestedNodesRequest{}

	if req.OutputMask == nil || req.OutputMask.Selectors {
		listReq.FetchSelectors = true
	}
	// Parse proto filter into datastore request
	if req.Filter != nil {
		filter := req.Filter
		listReq.ByAttestationType = filter.ByAttestationType
		listReq.ByBanned = filter.ByBanned

		if filter.BySelectorMatch != nil {
			selectors, err := api.SelectorsFromProto(filter.BySelectorMatch.Selectors)
			if err != nil {
				log.WithError(err).Error("Failed to parse selectors")
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse selectors: %v", err)
			}
			listReq.BySelectorMatch = &datastore.BySelectors{
				Match:     datastore.BySelectors_MatchBehavior(filter.BySelectorMatch.Match),
				Selectors: selectors,
			}
		}
	}

	// Set pagination parameters
	if req.PageSize > 0 {
		listReq.Pagination = &datastore.Pagination{
			PageSize: req.PageSize,
			Token:    req.PageToken,
		}
	}

	dsResp, err := s.ds.ListAttestedNodes(ctx, listReq)
	if err != nil {
		log.WithError(err).Error("Failed to list agents")
		return nil, status.Errorf(codes.Internal, "failed to list agents: %v", err)
	}

	resp := &agent.ListAgentsResponse{}

	if dsResp.Pagination != nil {
		resp.NextPageToken = dsResp.Pagination.Token
	}

	// Parse nodes into proto and apply output mask
	for _, node := range dsResp.Nodes {
		a, err := api.ProtoFromAttestedNode(node)
		if err != nil {
			log.WithError(err).WithField(telemetry.SPIFFEID, node.SpiffeId).Warn("Unable to parse attested node")
			continue
		}

		applyMask(a, req.OutputMask)
		resp.Agents = append(resp.Agents, a)
	}

	return resp, nil
}

func (s *Service) GetAgent(ctx context.Context, req *agent.GetAgentRequest) (*types.Agent, error) {
	log := rpccontext.Logger(ctx)

	agentID, err := api.IDFromProto(req.Id)
	if err != nil {
		log.WithError(err).Error("Failed to parse agent ID")
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse agent ID: %v", err)
	}

	err = idutil.ValidateSpiffeID(agentID.String(), idutil.AllowTrustDomainAgent(s.td.String()))
	if err != nil {
		log.WithError(err).Error("Not a valid agent ID")
		return nil, status.Errorf(codes.Internal, "not a valid agent ID: %v", err)
	}

	log = log.WithField(telemetry.SPIFFEID, agentID.String())
	resp, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
		SpiffeId: agentID.String(),
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
	log := rpccontext.Logger(ctx)

	id, err := api.IDFromProto(req.Id)
	if err != nil {
		log.WithError(err).Error("Invalid request: invalid SPIFFE ID")
		return nil, status.Errorf(codes.InvalidArgument, "invalid SPIFFE ID: %v", err)
	}

	log = log.WithField(telemetry.SPIFFEID, id.String())

	if !idutil.IsAgentPath(id.Path()) {
		log.Error("Invalid request: not an agent ID")
		return nil, status.Error(codes.InvalidArgument, "not an agent ID")
	}

	if !id.MemberOf(s.td) {
		log.Error("Invalid request: cannot ban an agent that does not belong to this trust domain")
		return nil, status.Errorf(codes.InvalidArgument, "cannot ban an agent that does not belong to this trust domain")
	}

	_, err = s.ds.DeleteAttestedNode(ctx, &datastore.DeleteAttestedNodeRequest{
		SpiffeId: id.String(),
	})
	switch status.Code(err) {
	case codes.OK:
		log.Info("Agent deleted")
		return &empty.Empty{}, nil
	case codes.NotFound:
		log.WithError(err).Error("Agent not found")
		return nil, status.Error(codes.NotFound, "agent not found")
	default:
		log.WithError(err).Error("Failed to remove agent")
		return nil, status.Errorf(codes.Internal, "failed to remove agent: %v", err)
	}
}

func (s *Service) BanAgent(ctx context.Context, req *agent.BanAgentRequest) (*empty.Empty, error) {
	log := rpccontext.Logger(ctx)

	id, err := api.IDFromProto(req.Id)
	if err != nil {
		log.WithError(err).Error("Invalid request: invalid SPIFFE ID")
		return nil, status.Errorf(codes.InvalidArgument, "invalid SPIFFE ID: %v", err)
	}

	log = log.WithField(telemetry.SPIFFEID, id.String())

	if !idutil.IsAgentPath(id.Path()) {
		log.Error("Invalid request: not an agent ID")
		return nil, status.Error(codes.InvalidArgument, "not an agent ID")
	}

	if !id.MemberOf(s.td) {
		log.Error("Invalid request: cannot ban an agent that does not belong to this trust domain")
		return nil, status.Errorf(codes.InvalidArgument, "cannot ban an agent that does not belong to this trust domain")
	}

	// The agent "Banned" state is pointed out by setting its
	// serial numbers (current and new) to empty strings.
	_, err = s.ds.UpdateAttestedNode(ctx, &datastore.UpdateAttestedNodeRequest{
		SpiffeId: id.String(),
		InputMask: &common.AttestedNodeMask{
			CertSerialNumber:    true,
			NewCertSerialNumber: true,
		},
	})

	switch status.Code(err) {
	case codes.OK:
		log.Info("Agent banned")
		return &empty.Empty{}, nil
	case codes.NotFound:
		log.WithError(err).Error("Agent not found")
		return nil, status.Errorf(codes.NotFound, "agent not found: %v", err)
	default:
		log.WithError(err).Error("Unable to ban agent")
		return nil, status.Errorf(codes.Internal, "unable to ban agent: %v", err)
	}
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
