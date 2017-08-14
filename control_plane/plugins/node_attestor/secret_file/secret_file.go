package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/control-plane/plugins/common/proto"
	"github.com/spiffe/control-plane/plugins/node_attestor"
	"github.com/spiffe/control-plane/plugins/node_attestor/proto"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) Configure(config string) ([]string, error) {
	return []string{}, nil
}

func (SecretFilePlugin) GetPluginInfo() (*common.GetPluginInfoResponse, error) {
	return nil, nil
}

func (SecretFilePlugin) Attest(attestedData *proto.AttestRequest) (*proto.AttestResponse, error) {
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
