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
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
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
	"google.golang.org/protobuf/types/known/emptypb"
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
	agent.UnsafeAgentServer

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
				return nil, api.MakeErr(log, codes.InvalidArgument, "failed to parse selectors", err)
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
		return nil, api.MakeErr(log, codes.Internal, "failed to list agents", err)
	}

	resp := &agent.ListAgentsResponse{}

	if dsResp.Pagination != nil {
		resp.NextPageToken = dsResp.Pagination.Token
	}

	// Parse nodes into proto and apply output mask
	for _, node := range dsResp.Nodes {
		a, err := api.ProtoFromAttestedNode(node)
		if err != nil {
			log.WithError(err).WithField(telemetry.SPIFFEID, node.SpiffeId).Warn("Failed to parse agent")
			continue
		}

		applyMask(a, req.OutputMask)
		resp.Agents = append(resp.Agents, a)
	}

	return resp, nil
}

func (s *Service) GetAgent(ctx context.Context, req *agent.GetAgentRequest) (*types.Agent, error) {
	log := rpccontext.Logger(ctx)

	agentID, err := api.TrustDomainAgentIDFromProto(s.td, req.Id)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid agent ID", err)
	}

	log = log.WithField(telemetry.SPIFFEID, agentID.String())
	resp, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
		SpiffeId: agentID.String(),
	})
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to fetch agent", err)
	}

	if resp.Node == nil {
		return nil, api.MakeErr(log, codes.NotFound, "agent not found", err)
	}

	selectors, err := s.getSelectorsFromAgentID(ctx, resp.Node.SpiffeId)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to get selectors from agent", err)
	}

	agent, err := api.AttestedNodeToProto(resp.Node, selectors)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to convert attested node to agent", err)
	}

	applyMask(agent, req.OutputMask)
	return agent, nil
}

func (s *Service) DeleteAgent(ctx context.Context, req *agent.DeleteAgentRequest) (*emptypb.Empty, error) {
	log := rpccontext.Logger(ctx)

	id, err := api.TrustDomainAgentIDFromProto(s.td, req.Id)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid agent ID", err)
	}

	log = log.WithField(telemetry.SPIFFEID, id.String())

	_, err = s.ds.DeleteAttestedNode(ctx, &datastore.DeleteAttestedNodeRequest{
		SpiffeId: id.String(),
	})
	switch status.Code(err) {
	case codes.OK:
		log.Info("Agent deleted")
		return &emptypb.Empty{}, nil
	case codes.NotFound:
		return nil, api.MakeErr(log, codes.NotFound, "agent not found", err)
	default:
		return nil, api.MakeErr(log, codes.Internal, "failed to remove agent", err)
	}
}

func (s *Service) BanAgent(ctx context.Context, req *agent.BanAgentRequest) (*emptypb.Empty, error) {
	log := rpccontext.Logger(ctx)

	id, err := api.TrustDomainAgentIDFromProto(s.td, req.Id)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid agent ID", err)
	}

	log = log.WithField(telemetry.SPIFFEID, id.String())

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
		return &emptypb.Empty{}, nil
	case codes.NotFound:
		return nil, api.MakeErr(log, codes.NotFound, "agent not found", err)
	default:
		return nil, api.MakeErr(log, codes.Internal, "failed to ban agent", err)
	}
}

func (s *Service) AttestAgent(stream agent.Agent_AttestAgentServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		return api.MakeErr(log, status.Code(err), "rejecting request due to attest agent rate limiting", err)
	}

	req, err := stream.Recv()
	if err != nil {
		return api.MakeErr(log, codes.InvalidArgument, "failed to receive request from stream", err)
	}

	// validate
	params := req.GetParams()
	if err := validateAttestAgentParams(params); err != nil {
		return api.MakeErr(log, codes.InvalidArgument, "malformed param", err)
	}

	log = log.WithField(telemetry.NodeAttestorType, params.Data.Type)

	// attest
	var attestResp *nodeattestor.AttestResponse
	if params.Data.Type == "join_token" {
		attestResp, err = s.attestJoinToken(ctx, string(params.Data.Payload))
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
		return api.MakeErr(log, codes.Internal, "invalid agent id", err)
	}
	log = log.WithField(telemetry.AgentID, agentID)

	// fetch the agent/node to check if it was already attested or banned
	attestedNode, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
		SpiffeId: agentID,
	})
	if err != nil {
		return api.MakeErr(log, codes.Internal, "failed to fetch agent", err)
	}

	if attestedNode.Node != nil && nodeutil.IsAgentBanned(attestedNode.Node) {
		return api.MakeErr(log, codes.PermissionDenied, "failed to attest: agent is banned", nil)
	}

	// parse and sign CSR
	svid, err := s.signSvid(ctx, agentSpiffeID, params.Params.Csr, log)
	if err != nil {
		return err
	}

	// augment selectors with resolver
	augmentedSels, err := s.augmentSelectors(ctx, agentID, attestResp.Selectors, params.Data.Type)
	if err != nil {
		return api.MakeErr(log, codes.Internal, "failed to augment selectors", err)
	}
	// store augmented selectors
	_, err = s.ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  agentID,
			Selectors: augmentedSels,
		},
	})
	if err != nil {
		return api.MakeErr(log, codes.Internal, "failed to update selectors", err)
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
			return api.MakeErr(log, codes.Internal, "failed to create attested agent", err)
		}
	} else {
		req := &datastore.UpdateAttestedNodeRequest{
			SpiffeId:         agentID,
			CertNotAfter:     svid[0].NotAfter.Unix(),
			CertSerialNumber: svid[0].SerialNumber.String(),
		}
		if _, err := s.ds.UpdateAttestedNode(ctx, req); err != nil {
			return api.MakeErr(log, codes.Internal, "failed to update attested agent", err)
		}
	}

	// build and send response
	response := getAttestAgentResponse(agentSpiffeID, svid)

	if p, ok := peer.FromContext(ctx); ok {
		log = log.WithField(telemetry.Address, p.Addr.String())
	}
	log.Info("Agent attestation request completed")

	if err := stream.Send(response); err != nil {
		return api.MakeErr(log, codes.Internal, "failed to send response over stream", err)
	}

	return nil
}

func (s *Service) RenewAgent(ctx context.Context, req *agent.RenewAgentRequest) (*agent.RenewAgentResponse, error) {
	log := rpccontext.Logger(ctx)

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		return nil, api.MakeErr(log, status.Code(err), "rejecting request due to renew agent rate limiting", err)
	}

	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		return nil, api.MakeErr(log, codes.Internal, "caller ID missing from request context", nil)
	}

	log.Debug("Renewing agent SVID")

	if req.Params == nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "params cannot be nil", nil)
	}
	if len(req.Params.Csr) == 0 {
		return nil, api.MakeErr(log, codes.InvalidArgument, "missing CSR", nil)
	}

	agentSVID, err := s.signSvid(ctx, callerID, req.Params.Csr, log)
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
		return nil, api.MakeErr(log, codes.InvalidArgument, "ttl is required, you must provide one", nil)
	}

	// If provided, check that the AgentID is valid BEFORE creating the join token so we can fail early
	var agentID spiffeid.ID
	var err error
	if req.AgentId != nil {
		agentID, err = api.TrustDomainWorkloadIDFromProto(s.td, req.AgentId)
		if err != nil {
			return nil, api.MakeErr(log, codes.InvalidArgument, "invalid agent ID", err)
		}
		log.WithField(telemetry.SPIFFEID, agentID.String())
	}

	// Generate a token if one wasn't specified
	if req.Token == "" {
		u, err := uuid.NewV4()
		if err != nil {
			return nil, api.MakeErr(log, codes.Internal, "failed to generate token UUID", err)
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
		return nil, api.MakeErr(log, codes.Internal, "failed to create token", err)
	}

	if req.AgentId != nil {
		err := s.createJoinTokenRegistrationEntry(ctx, req.Token, agentID.String())
		if err != nil {
			return nil, api.MakeErr(log, codes.Internal, "failed to create join token registration entry", err)
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
		return err
	}
	return nil
}

func (s *Service) updateAttestedNode(ctx context.Context, req *datastore.UpdateAttestedNodeRequest, log logrus.FieldLogger) error {
	_, err := s.ds.UpdateAttestedNode(ctx, req)
	switch status.Code(err) {
	case codes.OK:
		return nil
	case codes.NotFound:
		return api.MakeErr(log, codes.NotFound, "agent not found", err)
	default:
		return api.MakeErr(log, codes.Internal, "failed to update agent", err)
	}
}

func (s *Service) signSvid(ctx context.Context, agentID spiffeid.ID, csr []byte, log logrus.FieldLogger) ([]*x509.Certificate, error) {
	parsedCsr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "failed to parse CSR", err)
	}

	// Sign a new X509 SVID
	x509Svid, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  agentID,
		PublicKey: parsedCsr.PublicKey,
	})
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to sign X509 SVID", err)
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
		return nil, api.MakeErr(log, codes.Internal, "failed to fetch join token", err)
	case resp.JoinToken == nil:
		return nil, api.MakeErr(log, codes.InvalidArgument, "failed to attest: join token does not exist or has already been used", nil)
	}

	_, err = s.ds.DeleteJoinToken(ctx, &datastore.DeleteJoinTokenRequest{
		Token: token,
	})
	switch {
	case err != nil:
		return nil, api.MakeErr(log, codes.Internal, "failed to delete join token", err)
	case time.Unix(resp.JoinToken.Expiry, 0).Before(s.clk.Now()):
		return nil, api.MakeErr(log, codes.InvalidArgument, "join token expired", nil)
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
		return nil, api.MakeErr(log, codes.FailedPrecondition, "could not find node attestor type", nil)
	}

	attestorStream, err := nodeAttestor.Attest(ctx)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to open stream with attestor", err)
	}

	attestRequest := &nodeattestor.AttestRequest{
		AttestationData: &common.AttestationData{
			Type: attestorType,
			Data: params.Data.Payload,
		},
	}
	var attestResp *nodeattestor.AttestResponse

	for {
		attestResp, err = attest(attestorStream, attestRequest)
		if err != nil {
			return nil, api.MakeErr(log, codes.Internal, "failed to attest", err)
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
			return nil, api.MakeErr(log, codes.Internal, "failed to send challenge to agent", err)
		}

		req, err := agentStream.Recv()
		if err != nil {
			return nil, api.MakeErr(log, codes.Internal, "failed to receive challenge from agent", err)
		}

		attestRequest = &nodeattestor.AttestRequest{
			Response: req.GetChallengeResponse(),
		}
	}

	if attestResp.AgentId == "" {
		return nil, api.MakeErr(log, codes.Internal, "failed to attest: AgentID response should not be empty", nil)
	}

	if err := attestorStream.CloseSend(); err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to close send stream", err)
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
	case len(params.Data.Payload) == 0:
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
