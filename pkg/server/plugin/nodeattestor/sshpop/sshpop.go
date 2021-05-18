package sshpop

import (
	"context"
	"sync"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/sshpop"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	nodeattestorv0 "github.com/spiffe/spire/proto/spire/plugin/server/nodeattestor/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Plugin struct {
	nodeattestorv0.UnsafeNodeAttestorServer

	mu        sync.RWMutex
	sshserver *sshpop.Server
}

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(sshpop.PluginName, nodeattestorv0.NodeAttestorPluginServer(p))
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Attest(stream nodeattestorv0.NodeAttestor_AttestServer) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.sshserver == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	handshaker := p.sshserver.NewHandshake()

	if pluginName := req.AttestationData.Type; pluginName != sshpop.PluginName {
		return status.Errorf(codes.InvalidArgument, "expected attestation type %q but got %q", sshpop.PluginName, pluginName)
	}
	if err := handshaker.VerifyAttestationData(req.AttestationData.Data); err != nil {
		return err
	}
	challenge, err := handshaker.IssueChallenge()
	if err != nil {
		return err
	}

	if err := stream.Send(&nodeattestorv0.AttestResponse{
		Challenge: challenge,
	}); err != nil {
		return err
	}

	responseReq, err := stream.Recv()
	if err != nil {
		return err
	}

	if err := handshaker.VerifyChallengeResponse(responseReq.Response); err != nil {
		return err
	}

	agentID, err := handshaker.AgentID()
	if err != nil {
		return err
	}

	return stream.Send(&nodeattestorv0.AttestResponse{
		AgentId: agentID,
	})
}

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	sshserver, err := sshpop.NewServer(req.GlobalConfig.GetTrustDomain(), req.Configuration)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.sshserver = sshserver
	p.mu.Unlock()
	return &plugin.ConfigureResponse{}, nil
}

func (*Plugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}
