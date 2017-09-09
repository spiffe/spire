package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/spire/pkg/agent/workloadattestor"
	"github.com/spiffe/spire/pkg/common/plugin"
)

type UnixPlugin struct{}

func (UnixPlugin) Attest(*workloadattestor.AttestRequest) (*workloadattestor.AttestResponse, error) {
	return &workloadattestor.AttestResponse{}, nil
}

func (UnixPlugin) Configure(*sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return &sriplugin.ConfigureResponse{}, nil
}

func (UnixPlugin) GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return &sriplugin.GetPluginInfoResponse{}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: workloadattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"wla_unix": workloadattestor.WorkloadAttestorPlugin{WorkloadAttestorImpl: &UnixPlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
