package sshpop

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/sshpop"
	"github.com/spiffe/spire/pkg/common/util/atomic"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
)

type Plugin struct {
	configured *atomic.Bool
	sshserver  *sshpop.Server
}

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(sshpop.PluginName, nodeattestor.PluginServer(p))
}

func New() *Plugin {
	return &Plugin{
		configured: atomic.NewBool(false),
	}
}

func (p *Plugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	if !p.configured.Get() {
		return sshpop.Errorf("not configured")
	}
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	handshaker := p.sshserver.NewHandshake()

	if pluginName := req.AttestationData.Type; pluginName != sshpop.PluginName {
		return sshpop.Errorf("expected attestation type %q but got %q", sshpop.PluginName, pluginName)
	}
	if err := handshaker.VerifyAttestationData(req.AttestationData.Data); err != nil {
		return err
	}
	challenge, err := handshaker.IssueChallenge()
	if err != nil {
		return err
	}

	if err := stream.Send(&nodeattestor.AttestResponse{
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

	spiffeid, err := handshaker.SpiffeID()
	if err != nil {
		return err
	}
	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: spiffeid,
	}

	if err := stream.Send(resp); err != nil {
		return err
	}
	return nil
}

func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	sshserver, err := sshpop.NewServer(req.GlobalConfig.GetTrustDomain(), req.Configuration)
	if err != nil {
		return nil, err
	}
	p.sshserver = sshserver
	p.configured.Set(true)
	return &plugin.ConfigureResponse{}, nil

}

func (*Plugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}
