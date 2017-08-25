package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/server/nodeattestor"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) Configure(config string) ([]string, error) {
	return []string{}, nil
}

func (SecretFilePlugin) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	return nil, nil
}

func (SecretFilePlugin) Attest(attestedData *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {
	return nil, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: nodeattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"na_secret_file": nodeattestor.NodeAttestorPlugin{NodeAttestorImpl: &SecretFilePlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
