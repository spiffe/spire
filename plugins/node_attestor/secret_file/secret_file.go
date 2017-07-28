package secretfile

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/control-plane/plugins/node_attestor"
	"github.com/spiffe/control-plane/plugins/node_attestor/proto"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) Attest(attestedData *proto.AttestedData) (*proto.AttestResponse, error) {
	return nil, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: nodeattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"nodeattestor": nodeattestor.NodeAttestorPlugin{NodeAttestorImpl: &SecretFilePlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
