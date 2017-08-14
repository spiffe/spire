package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/node_agent/plugins/common/proto"
	"github.com/spiffe/sri/node_agent/plugins/key_manager"
	"github.com/spiffe/sri/node_agent/plugins/key_manager/proto"
)

type MemoryPlugin struct{}

func (MemoryPlugin) GenerateKeyPair(*node_agent_proto.GenerateKeyPairRequest) (*node_agent_proto.GenerateKeyPairResponse, error) {
	return &node_agent_proto.GenerateKeyPairResponse{}, nil
}

func (MemoryPlugin) FetchPrivateKey(*node_agent_proto.FetchPrivateKeyRequest) (*node_agent_proto.FetchPrivateKeyResponse, error) {
	return &node_agent_proto.FetchPrivateKeyResponse{}, nil
}

func (MemoryPlugin) Configure(*common.ConfigureRequest) (*common.ConfigureResponse, error) {
	return &common.ConfigureResponse{}, nil
}

func (MemoryPlugin) GetPluginInfo(*common.GetPluginInfoRequest) (*common.GetPluginInfoResponse, error) {
	return &common.GetPluginInfoResponse{}, nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: keymanager.Handshake,
		Plugins: map[string]plugin.Plugin{
			"km_memory": keymanager.KeyManagerPlugin{KeyManagerImpl: &MemoryPlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
