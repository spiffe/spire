package tailscale

import (
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	common "github.com/spiffe/spire/pkg/common/plugin/tailscale"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(common.PluginName,
		nodeattestorv1.NodeAttestorPluginServer(p))
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	// Send a minimal payload. The server identifies the agent via the
	// Tailscale whois API using the peer's Tailscale IP address, so no
	// attestation data is needed from the agent side.
	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: []byte("{}"),
		},
	})
}
