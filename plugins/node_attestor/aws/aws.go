package aws

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/node-agent/plugins/node_attestor"
)

type AwsPlugin struct{}

func (AwsPlugin) FetchAttestationData() (attestationData []byte, err error) {
	return []byte{}, nil
}

func (AwsPlugin) Configure(configuration string) error {
	return nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: nodeattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"nodeattestor": nodeattestor.NodeAttestorPlugin{NodeAttestorImpl: &AwsPlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
