package secretfile

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/node-agent/plugins/node_attestor"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) FetchAttestationData() (attestationData []byte, err error) {
	return []byte{}, nil
}

func (SecretFilePlugin) Configure(configuration string) error {
	return nil
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
