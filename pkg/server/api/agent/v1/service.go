package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"path"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/server/plugin/noderesolver"
	"github.com/spiffe/spire/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// RegisterService registers the agent service on the gRPC server/
func RegisterService(s *grpc.Server, service *Service) {
	agent.RegisterAgentServer(s, service)
}

// Config is the service configuration
type Config struct {
	Catalog     catalog.Catalog
	Clock       clock.Clock
	DataStore   datastore.DataStore
	ServerCA    ca.ServerCA
	TrustDomain spiffeid.TrustDomain
}

// New creates a new agent service
func New(config Config) *Service {
	return &Service{
		cat: config.Catalog,
		clk: config.Clock,
		ds:  config.DataStore,
		ca:  config.ServerCA,
		td:  config.TrustDomain,
	}
}

// Service implements the v1 agent service
type Service struct {
	cat catalog.Catalog
	clk clock.Clock
	ds  datastore.DataStore
	ca  ca.ServerCA
	td  spiffeid.TrustDomain
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
		log.Error("Invalid request: cannot delete an agent that does not belong to this trust domain")
		return nil, status.Errorf(codes.InvalidArgument, "cannot delete an agent that does not belong to this trust domain")
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
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		log.WithError(err).Error("Rejecting request due to attest agent rate limiting")
		return err
	}

	req, err := stream.Recv()
	if err != nil {
		log.WithError(err).Error("Failed to receive request from stream")
		return status.Errorf(codes.InvalidArgument, "failed to receive request from stream: %v", err)
	}

	// validate
	params := req.GetParams()
	if err := validateAttestAgentParams(params); err != nil {
		log.WithError(err).Error("Invalid request: malformed param")
		return status.Errorf(codes.InvalidArgument, "malformed param: %v", err)
	}

	log = log.WithField(telemetry.NodeAttestorType, params.Data.Type)

	// attest
	var attestResp *nodeattestor.AttestResponse
	if params.Data.Type == "join_token" {
		attestResp, err = s.attestJoinToken(ctx, params.Data.Payload)
		if err != nil {
			return err
		}
	} else {
		attestResp, err = s.attestChallengeResponse(ctx, stream, params)
		if err != nil {
			return err
		}
	}

	agentID := attestResp.AgentId
	agentSpiffeID, err := spiffeid.FromString(agentID)
	if err != nil {
		log.WithError(err).Error("Invalid agent id")
		return status.Error(codes.Internal, "invalid agent id")
	}
	log = log.WithField(telemetry.AgentID, agentID)

	// fetch the agent/node to check if it was already attested or banned
	attestedNode, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
		SpiffeId: agentID,
	})
	if err != nil {
		log.WithError(err).Error("Failed to fetch agent")
		return status.Error(codes.Internal, "failed to fetch agent")
	}

	if attestedNode.Node != nil && nodeutil.IsAgentBanned(attestedNode.Node) {
		log.Error("Failed to attest: agent is banned")
		return status.Error(codes.PermissionDenied, "failed to attest: agent is banned")
	}

	// parse and sign CSR
	svid, err := s.signSvid(ctx, &agentSpiffeID, params.Params.Csr, log)
	if err != nil {
		return err
	}

	// augment selectors with resolver
	augmentedSels, err := s.augmentSelectors(ctx, agentID, attestResp.Selectors, params.Data.Type)
	if err != nil {
		log.WithError(err).Error("Failed to augment selectors")
		return status.Error(codes.Internal, "failed to augment selectors")
	}
	// store augmented selectors
	_, err = s.ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  agentID,
			Selectors: augmentedSels,
		},
	})
	if err != nil {
		log.WithError(err).Error("Failed to update selectors")
		return status.Error(codes.Internal, "failed to update selectors")
	}

	// create or update attested entry
	if attestedNode.Node == nil {
		req := &datastore.CreateAttestedNodeRequest{
			Node: &common.AttestedNode{
				AttestationDataType: params.Data.Type,
				SpiffeId:            agentID,
				CertNotAfter:        svid[0].NotAfter.Unix(),
				CertSerialNumber:    svid[0].SerialNumber.String(),
			}}
		if _, err := s.ds.CreateAttestedNode(ctx, req); err != nil {
			log.WithError(err).Error("Failed to create attested agent")
			return status.Error(codes.Internal, "failed to create attested agent")
		}
	} else {
		req := &datastore.UpdateAttestedNodeRequest{
			SpiffeId:         agentID,
			CertNotAfter:     svid[0].NotAfter.Unix(),
			CertSerialNumber: svid[0].SerialNumber.String(),
		}
		if _, err := s.ds.UpdateAttestedNode(ctx, req); err != nil {
			log.WithError(err).Error("Failed to update attested agent")
			return status.Error(codes.Internal, "failed to update attested agent")
		}
	}

	// build and send response
	response := getAttestAgentResponse(agentSpiffeID, svid)

	if p, ok := peer.FromContext(ctx); ok {
		log = log.WithField(telemetry.Address, p.Addr.String())
	}
	log.Info("Agent attestation request completed")

	if err := stream.Send(response); err != nil {
		log.WithError(err).Error("Failed to send response over stream")
		return status.Errorf(codes.Internal, "failed to send response over stream: %v", err)
	}

	return nil
}

func (s *Service) RenewAgent(ctx context.Context, req *agent.RenewAgentRequest) (*agent.RenewAgentResponse, error) {
	log := rpccontext.Logger(ctx)

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		log.WithError(err).Error("Rejecting request due to renew agent rate limiting")
		return nil, err
	}

	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		log.Error("Caller ID missing from request context")
		return nil, status.Error(codes.Internal, "caller ID missing from request context")
	}

	log.Debug("Renewing agent SVID")

	if req.Params == nil {
		log.Error("Invalid argument: params cannot be nil")
		return nil, status.Error(codes.InvalidArgument, "params cannot be nil")
	}
	if len(req.Params.Csr) == 0 {
		log.Error("Invalid argument: missing CSR")
		return nil, status.Error(codes.InvalidArgument, "missing CSR")
	}

	agentSVID, err := s.signSvid(ctx, &callerID, req.Params.Csr, log)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	// Send response with new X509 SVID
	return &agent.RenewAgentResponse{
		Svid: &types.X509SVID{
			Id:        api.ProtoFromID(callerID),
			ExpiresAt: agentSVID[0].NotAfter.Unix(),
			CertChain: x509util.RawCertsFromCertificates(agentSVID),
		},
	}, nil
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

func (s *Service) signSvid(ctx context.Context, agentID *spiffeid.ID, csr []byte, log logrus.FieldLogger) ([]*x509.Certificate, error) {
	parsedCsr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		log.WithError(err).Error("Invalid argument: failed to parse CSR")
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse CSR: %v", err)
	}

	// Sign a new X509 SVID
	x509Svid, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  agentID.String(),
		PublicKey: parsedCsr.PublicKey,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign X509 SVID")
		return nil, status.Errorf(codes.Internal, "failed to sign X509 SVID: %v", err)
	}

	return x509Svid, nil
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

func (s *Service) attestJoinToken(ctx context.Context, token string) (*nodeattestor.AttestResponse, error) {
	log := rpccontext.Logger(ctx).WithField(telemetry.NodeAttestorType, "join_token")

	resp, err := s.ds.FetchJoinToken(ctx, &datastore.FetchJoinTokenRequest{
		Token: token,
	})
	switch {
	case err != nil:
		log.WithError(err).Error("Failed to fetch join token")
		return nil, status.Error(codes.Internal, "failed to fetch join token")
	case resp.JoinToken == nil:
		log.Error("Failed to attest: join token does not exist or has already been used")
		return nil, status.Error(codes.InvalidArgument, "failed to attest: join token does not exist or has already been used")
	}

	_, err = s.ds.DeleteJoinToken(ctx, &datastore.DeleteJoinTokenRequest{
		Token: token,
	})
	switch {
	case err != nil:
		log.WithError(err).Error("Failed to delete join token")
		return nil, status.Error(codes.Internal, "failed to delete join token")
	case time.Unix(resp.JoinToken.Expiry, 0).Before(s.clk.Now()):
		log.Error("Join token expired")
		return nil, status.Error(codes.InvalidArgument, "join token expired")
	}

	tokenPath := path.Join("spire", "agent", "join_token", token)
	return &nodeattestor.AttestResponse{
		AgentId: s.td.NewID(tokenPath).String(),
	}, nil
}

func (s *Service) attestChallengeResponse(ctx context.Context, agentStream agent.Agent_AttestAgentServer, params *agent.AttestAgentRequest_Params) (*nodeattestor.AttestResponse, error) {
	attestorType := params.Data.Type
	log := rpccontext.Logger(ctx).WithField(telemetry.NodeAttestorType, attestorType)

	nodeAttestor, ok := s.cat.GetNodeAttestorNamed(attestorType)
	if !ok {
		log.Error("Could not find node attestor type")
		return nil, status.Errorf(codes.FailedPrecondition, "could not find node attestor type %q", attestorType)
	}

	attestorStream, err := nodeAttestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Unable to open stream with attestor")
		return nil, status.Error(codes.Internal, "unable to open stream with attestor")
	}

	attestRequest := &nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: attestorType,
			Data: []byte(params.Data.Payload),
		},
	}
	var attestResp *nodeattestor.AttestResponse

	for {
		attestResp, err = attest(attestorStream, attestRequest)
		if err != nil {
			log.WithError(err).Error("Failed to attest")
			return nil, status.Error(codes.Internal, "failed to attest")
		}
		// Without a challenge we are done. Otherwise we need to continue the challenge/response flow
		if attestResp.Challenge == nil {
			break
		}

		resp := &agent.AttestAgentResponse{
			Step: &agent.AttestAgentResponse_Challenge{
				Challenge: attestResp.Challenge,
			},
		}
		if err := agentStream.Send(resp); err != nil {
			log.WithError(err).Error("Failed to send challenge to agent")
			return nil, status.Error(codes.Internal, "failed to send challenge to agent")
		}

		req, err := agentStream.Recv()
		if err != nil {
			log.WithError(err).Error("Failed to receive challenge from agent")
			return nil, status.Error(codes.Internal, "failed to receive challenge from agent")
		}

		attestRequest = &nodeattestor.AttestRequest{
			Response: req.GetChallengeResponse(),
		}
	}

	if attestResp.AgentId == "" {
		log.WithError(err).Error("Failed to attest: AgentID response should not be empty")
		return nil, status.Error(codes.Internal, "failed to attest: AgentID response should not be empty")
	}

	if err := attestorStream.CloseSend(); err != nil {
		log.WithError(err).Error("Failed to close send stream")
		return nil, status.Errorf(codes.Internal, "failed to close send stream: %v", err)
	}
	if _, err := attestorStream.Recv(); err != io.EOF {
		log.WithError(err).Warn("Expected EOF on attestation stream")
	}

	return attestResp, nil
}

func (s *Service) augmentSelectors(ctx context.Context, agentID string, selectors []*common.Selector, attestationType string) ([]*common.Selector, error) {
	log := rpccontext.Logger(ctx).
		WithField(telemetry.AgentID, agentID).
		WithField(telemetry.NodeAttestorType, attestationType)

	// Select node resolver based on request attestation type
	nodeResolver, ok := s.cat.GetNodeResolverNamed(attestationType)
	if !ok {
		log.Debug("Could not find node resolver")
		return selectors, nil
	}

	//Call node resolver plugin to get a map of spiffeID=>Selector
	response, err := nodeResolver.Resolve(ctx, &noderesolver.ResolveRequest{
		BaseSpiffeIdList: []string{agentID},
	})
	if err != nil {
		return nil, err
	}
	if resolved := response.Map[agentID]; resolved != nil {
		selectors = append(selectors, resolved.Entries...)
	}

	return selectors, nil
}

func applyMask(a *types.Agent, mask *types.AgentMask) {
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

func validateAttestAgentParams(params *agent.AttestAgentRequest_Params) error {
	switch {
	case params == nil:
		return errors.New("missing params")
	case params.Data == nil:
		return errors.New("missing attestation data")
	case params.Params == nil:
		return errors.New("missing X509-SVID parameters")
	case len(params.Params.Csr) == 0:
		return errors.New("missing CSR")
	case params.Data.Type == "":
		return errors.New("missing attestation data type")
	case params.Data.Payload == "":
		return errors.New("missing attestation data payload")
	default:
		return nil
	}
}

func attest(attestorStream nodeattestor.NodeAttestor_AttestClient, attestRequest *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
	if err := attestorStream.Send(attestRequest); err != nil {
		return nil, err
	}
	return attestorStream.Recv()
}

func getAttestAgentResponse(spiffeID spiffeid.ID, certificates []*x509.Certificate) *agent.AttestAgentResponse {
	svid := &types.X509SVID{
		Id:        api.ProtoFromID(spiffeID),
		CertChain: x509util.RawCertsFromCertificates(certificates),
		ExpiresAt: certificates[0].NotAfter.Unix(),
	}

	return &agent.AttestAgentResponse{
		Step: &agent.AttestAgentResponse_Result_{
			Result: &agent.AttestAgentResponse_Result{
				Svid: svid,
			},
		},
	}
}
