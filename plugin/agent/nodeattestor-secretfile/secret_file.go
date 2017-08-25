package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/agent/nodeattestor"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) FetchAttestationData(*nodeattestor.FetchAttestationDataRequest) (*nodeattestor.FetchAttestationDataResponse, error) {
	return &nodeattestor.FetchAttestationDataResponse{}, nil
}

func (SecretFilePlugin) Configure(*sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return &sriplugin.ConfigureResponse{}, nil
}

func (SecretFilePlugin) GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return &sriplugin.GetPluginInfoResponse{}, nil
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
