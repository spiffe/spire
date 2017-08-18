package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/common/plugins/common/proto"
	"github.com/spiffe/sri/node_agent/plugins/workload_attestor"
	"github.com/spiffe/sri/node_agent/plugins/workload_attestor/proto"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) Attest(*sri_proto.AttestRequest) (*sri_proto.AttestResponse, error) {
	return &sri_proto.AttestResponse{}, nil
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
