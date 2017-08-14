package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/control_plane/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/node_attestor"
	"github.com/spiffe/sri/control_plane/plugins/node_attestor/proto"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) Configure(config string) ([]string, error) {
	return []string{}, nil
}

func (SecretFilePlugin) GetPluginInfo() (*common.GetPluginInfoResponse, error) {
	return nil, nil
}

func (SecretFilePlugin) Attest(attestedData *control_plane_proto.AttestRequest) (*control_plane_proto.AttestResponse, error) {
	return nil, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: control_plane_nodeattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"na_secret_file": control_plane_nodeattestor.NodeAttestorPlugin{NodeAttestorImpl: &SecretFilePlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
