package sshpop

import (
	"context"
	"sync"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/sshpop"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	mu        sync.RWMutex
	sshserver *sshpop.Server
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(sshpop.PluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	if p.sshserver == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	handshaker := p.sshserver.NewHandshake()
	if err := handshaker.VerifyAttestationData(payload); err != nil {
		return err
	}
	challenge, err := handshaker.IssueChallenge()
	if err != nil {
		return err
	}

	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challenge,
		},
	}); err != nil {
		return err
	}

	responseReq, err := stream.Recv()
	if err != nil {
		return err
	}

	if err := handshaker.VerifyChallengeResponse(responseReq.GetChallengeResponse()); err != nil {
		return err
	}

	agentID, err := handshaker.AgentID()
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create AgentID: %v", err)
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				CanReattest: true,
				SpiffeId:    agentID.String(),
			},
		},
	})
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}
	sshserver, err := sshpop.NewServer(req.CoreConfiguration.GetTrustDomain(), req.HclConfiguration)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.sshserver = sshserver
	p.mu.Unlock()
	return &configv1.ConfigureResponse{}, nil
}
