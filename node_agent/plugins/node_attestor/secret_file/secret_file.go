package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/node_agent/plugins/common/proto"
	"github.com/spiffe/sri/node_agent/plugins/node_attestor"
	"github.com/spiffe/sri/node_agent/plugins/node_attestor/proto"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) FetchAttestationData(*node_agent_proto.FetchAttestationDataRequest) (*node_agent_proto.FetchAttestationDataResponse, error) {
	return &node_agent_proto.FetchAttestationDataResponse{}, nil
}

func (SecretFilePlugin) Configure(*common.ConfigureRequest) (*common.ConfigureResponse, error) {
	return &common.ConfigureResponse{}, nil
}

func (SecretFilePlugin) GetPluginInfo(*common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	return &common.GetPluginInfoResponse{}, nil
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
