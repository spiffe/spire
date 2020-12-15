package sshpop

import (
	"context"
	"sync"

	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/sshpop"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/common/plugin"
)

type Plugin struct {
	nodeattestor.UnsafeNodeAttestorServer

	mu        sync.RWMutex
	sshclient *sshpop.Client
}

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(sshpop.PluginName, nodeattestor.PluginServer(p))
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) (err error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.sshclient == nil {
		return sshpop.Errorf("not configured")
	}
	handshaker := p.sshclient.NewHandshake()

	attestationData, err := handshaker.AttestationData()
	if err != nil {
		return err
	}
	if err := stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &common.AttestationData{
			Type: sshpop.PluginName,
			Data: attestationData,
		},
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
	p.mu.Lock()
	p.sshclient = sshclient
	p.mu.Unlock()
	return &plugin.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (*Plugin) GetPluginInfo(context.Context, *plugin.GetPluginInfoRequest) (*plugin.GetPluginInfoResponse, error) {
	return &plugin.GetPluginInfoResponse{}, nil
}
