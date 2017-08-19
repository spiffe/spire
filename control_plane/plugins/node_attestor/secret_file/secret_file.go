package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/common/plugin"
	"github.com/spiffe/sri/control_plane/plugins/node_attestor"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) Configure(config string) ([]string, error) {
	return []string{}, nil
}

func (SecretFilePlugin) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	return nil, nil
}

func (SecretFilePlugin) Attest(attestedData *cpnodeattestor.AttestRequest) (*cpnodeattestor.AttestResponse, error) {
	return nil, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: cpnodeattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"na_secret_file": cpnodeattestor.NodeAttestorPlugin{NodeAttestorImpl: &SecretFilePlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
