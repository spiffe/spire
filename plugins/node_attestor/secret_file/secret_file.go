package secretfile

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/node-agent/plugins/common/proto"
	"github.com/spiffe/node-agent/plugins/node_attestor"
	"github.com/spiffe/node-agent/plugins/node_attestor/proto"
)

type SecretFilePlugin struct{}

func (SecretFilePlugin) FetchAttestationData(*proto.FetchAttestationDataRequest) (*proto.FetchAttestationDataResponse, error) {
	return &proto.FetchAttestationDataResponse{}, nil
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
			"nodeattestor": nodeattestor.NodeAttestorPlugin{NodeAttestorImpl: &SecretFilePlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
