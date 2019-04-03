package sshpop

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/sshpop"
	"github.com/spiffe/spire/pkg/common/util/atomic"
	"github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
)

type Plugin struct {
	configured *atomic.Bool
	sshclient  *sshpop.Client
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

func (p *Plugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) (err error) {
	if !p.configured.Get() {
		return sshpop.Errorf("not configured")
	}
	handshaker := p.sshclient.NewHandshake()
	spiffeid, err := handshaker.SpiffeID()
	if err != nil {
		return err
	}

	attestationData, err := handshaker.AttestationData()
	if err != nil {
		return err
	}
	if err := stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: sshpop.PluginName,
			Data: attestationData,
		},
		SpiffeId: spiffeid,
	}); err != nil {
		return err
	}

	challengeReq, err := stream.Recv()
	if err != nil {
		return err
	}
	challengeRes, err := handshaker.RespondToChallenge(challengeReq.Challenge)
	if err != nil {
		return err
	}

	if err := stream.Send(&nodeattestor.FetchAttestationDataResponse{
		SpiffeId: spiffeid,
		Response: challengeRes,
	}); err != nil {
		return err
	}
	return nil
}

// Configure configures the Plugin.
func (p *Plugin) Configure(ctx context.Context, req *plugin.ConfigureRequest) (*plugin.ConfigureResponse, error) {
	sshclient, err := sshpop.NewClient(req.GlobalConfig.GetTrustDomain(), req.Configuration)
	if err != nil {
		return nil, err
	}
	p.sshclient = sshclient
	p.configured.Set(true)
	return &plugin.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (*Plugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}
