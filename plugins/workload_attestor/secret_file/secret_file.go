package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/node-agent/plugins/common/proto"
	"github.com/spiffe/node-agent/plugins/workload_attestor"
	"github.com/spiffe/node-agent/plugins/workload_attestor/proto"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) Attest(*proto.AttestRequest) (*proto.AttestResponse, error) {
	return &proto.AttestResponse{}, nil
}

func (SecretFilePlugin) Configure(*common.ConfigureRequest) (*common.ConfigureResponse, error) {
	return &common.ConfigureResponse{}, nil
}

func (SecretFilePlugin) GetPluginInfo(*common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	return &common.GetPluginInfoResponse{}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: workloadattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"wla_secret_file": workloadattestor.WorkloadAttestorPlugin{WorkloadAttestorImpl: &SecretFilePlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
