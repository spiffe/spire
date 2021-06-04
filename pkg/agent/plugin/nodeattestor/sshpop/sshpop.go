package sshpop

import (
	"context"
	"sync"

	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
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
	sshclient *sshpop.Client
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

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) (err error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.sshclient == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}
	handshaker := p.sshclient.NewHandshake()

	payload, err := handshaker.AttestationData()
	if err != nil {
		return err
	}
	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: payload,
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

	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: challengeRes,
		},
	})
}

// Configure configures the Plugin.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	sshclient, err := sshpop.NewClient(req.HclConfiguration)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.sshclient = sshclient
	p.mu.Unlock()
	return &configv1.ConfigureResponse{}, nil
}
