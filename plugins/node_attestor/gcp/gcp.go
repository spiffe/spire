package gcp

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/node-agent/plugins/node_attestor"
)

type GcpPlugin struct{}

func (GcpPlugin) FetchAttestationData() (attestationData []byte, err error) {
	return []byte{}, nil
}

func (GcpPlugin) Configure(configuration string) error {
	return nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: nodeattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"nodeattestor": nodeattestor.NodeAttestorPlugin{NodeAttestorImpl: &GcpPlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
