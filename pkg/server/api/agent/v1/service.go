package agent

import (
	"context"
	"crypto/x509"
	"fmt"
	"path"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca"
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
	ServerCA    ca.ServerCA
	TrustDomain spiffeid.TrustDomain
}

// New creates a new agent service
func New(config Config) *Service {
	return &Service{
		ca: config.ServerCA,
		ds: config.DataStore,
		td: config.TrustDomain,
	}
}

// Service implements the v1 agent service
type Service struct {
	ca ca.ServerCA
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
	ctx := stream.Context()

	log := rpccontext.Logger(ctx)

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		log.WithError(err).Error("Rejecting request due to renew agent rate limiting")
		return err
	}

	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		log.Error("Caller ID missing from request context")
		return status.Error(codes.Internal, "caller ID missing from request context")
	}

	log.Debug("Renewing agent SVID")

	req, err := stream.Recv()
	if err != nil {
		log.WithError(err).Error("Failed to receive request from stream")
		return status.Error(codes.InvalidArgument, err.Error())
	}

	params, ok := req.Step.(*agent.RenewAgentRequest_Params)
	if !ok {
		log.Errorf("Invalid argument: expected params step but got %T", params)
		return status.Errorf(codes.InvalidArgument, "expected params step but got %T", params)
	}

	agentSVID, err := s.signSvid(ctx, &callerID, params, log)
	if err != nil {
		return err
	}

	if err := s.updateAttestedNode(ctx, &datastore.UpdateAttestedNodeRequest{
		InputMask: &common.AttestedNodeMask{
			NewCertNotAfter:     true,
			NewCertSerialNumber: true,
		},
		SpiffeId:            callerID.String(),
		NewCertNotAfter:     agentSVID[0].NotAfter.Unix(),
		NewCertSerialNumber: agentSVID[0].SerialNumber.String(),
	}, log); err != nil {
		return err
	}

	// Send response with new X509 SVID
	if err := stream.Send(&agent.RenewAgentResponse{
		Svid: &types.X509SVID{
			Id:        api.ProtoFromID(callerID),
			ExpiresAt: agentSVID[0].NotAfter.Unix(),
			CertChain: x509util.RawCertsFromCertificates(agentSVID),
		},
	}); err != nil {
		log.WithError(err).Error("Failed to send response")
		return status.Errorf(codes.Internal, "failed to send response: %v", err)
	}

	// Wait until get ACK
	req, err = stream.Recv()
	if err != nil {
		log.WithError(err).Error("Failed to receive ack from stream")
		return status.Error(codes.InvalidArgument, err.Error())
	}

	ack, ok := req.Step.(*agent.RenewAgentRequest_Ack_)
	if !ok {
		log.Errorf("Invalid argument: expected ack step but got %T", ack)
		return status.Errorf(codes.InvalidArgument, "expected ack step but got %T", ack)
	}

	return s.updateAttestedNode(ctx, &datastore.UpdateAttestedNodeRequest{
		SpiffeId:         callerID.String(),
		CertNotAfter:     agentSVID[0].NotAfter.Unix(),
		CertSerialNumber: agentSVID[0].SerialNumber.String(),
	}, log)
}

func (s *Service) updateAttestedNode(ctx context.Context, req *datastore.UpdateAttestedNodeRequest, log logrus.FieldLogger) error {
	_, err := s.ds.UpdateAttestedNode(ctx, req)
	switch status.Code(err) {
	case codes.OK:
		return nil
	case codes.NotFound:
		log.WithError(err).Error("Agent not found")
		return status.Errorf(codes.NotFound, "agent not found: %v", err)
	default:
		log.WithError(err).Error("Failed to update agent")
		return status.Errorf(codes.Internal, "failed to update agent: %v", err)
	}
}

func (s *Service) signSvid(ctx context.Context, agentID *spiffeid.ID, step *agent.RenewAgentRequest_Params, log logrus.FieldLogger) ([]*x509.Certificate, error) {
	if len(step.Params.Csr) == 0 {
		log.Error("Invalid argument: missing CSR")
		return nil, status.Error(codes.InvalidArgument, "missing CSR")
	}

	csr, err := x509.ParseCertificateRequest(step.Params.Csr)
	if err != nil {
		log.WithError(err).Error("Invalid argument: failed to parse CSR")
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse CSR: %v", err)
	}

	// Sign a new X509 SVID
	x509Svid, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  agentID.String(),
		PublicKey: csr.PublicKey,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign X509 SVID")
		return nil, status.Errorf(codes.Internal, "failed to sign X509 SVID: %v", err)
	}

	return x509Svid, nil
}

func (s *Service) CreateJoinToken(ctx context.Context, req *agent.CreateJoinTokenRequest) (*types.JoinToken, error) {
	log := rpccontext.Logger(ctx)

	if req.Ttl < 1 {
		log.Error("TTL is required")
		return nil, status.Error(codes.InvalidArgument, "ttl is required, you must provide one")
	}

	// If provided, check that the AgentID is valid BEFORE creating the join token so we can fail early
	var agentID spiffeid.ID
	var err error
	if req.AgentId != nil {
		agentID, err = api.IDFromProto(req.AgentId)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid spiffe ID: %v", err)
		}
		if agentID.TrustDomain() != s.td {
			return nil, status.Errorf(codes.InvalidArgument, "requested agent SPIFFE ID does not match server trust domain")
		}
	}

	// Generate a token if one wasn't specified
	if req.Token == "" {
		u, err := uuid.NewV4()
		if err != nil {
			log.WithError(err).Error("Failed to generate token UUID")
			return nil, status.Errorf(codes.Internal, "failed to generate token UUID: %v", err)
		}
		req.Token = u.String()
	}

	expiry := time.Now().Unix() + int64(req.Ttl)

	result, err := s.ds.CreateJoinToken(ctx, &datastore.CreateJoinTokenRequest{
		JoinToken: &datastore.JoinToken{
			Token:  req.Token,
			Expiry: expiry,
		},
	})
	if err != nil {
		log.WithError(err).Error("Failed to create token")
		return nil, status.Errorf(codes.Internal, "failed to create token: %v", err)
	}

	if req.AgentId != nil {
		err := s.createJoinTokenRegistrationEntry(ctx, req.Token, agentID.String())
		if err != nil {
			return nil, err
		}
	}

	return &types.JoinToken{Value: result.JoinToken.Token, ExpiresAt: expiry}, nil
}

func (s *Service) createJoinTokenRegistrationEntry(ctx context.Context, token string, agentID string) error {
	parentID := s.td.NewID(path.Join("spire", "agent", "join_token", token))
	req := &datastore.CreateRegistrationEntryRequest{
		Entry: &common.RegistrationEntry{
			ParentId: parentID.String(),
			SpiffeId: agentID,
			Selectors: []*common.Selector{
				{Type: "spiffe_id", Value: parentID.String()},
			},
		},
	}
	_, err := s.ds.CreateRegistrationEntry(ctx, req)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create join token registration entry: %v", err)
	}
	return nil
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
