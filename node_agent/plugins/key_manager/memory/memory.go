package main

import (
	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/common/plugins/common/proto"
	"github.com/spiffe/sri/node_agent/plugins/key_manager"
	"github.com/spiffe/sri/node_agent/plugins/key_manager/proto"
)

type MemoryPlugin struct{}

func (MemoryPlugin) GenerateKeyPair(*sri_proto.GenerateKeyPairRequest) (*sri_proto.GenerateKeyPairResponse, error) {
	return &sri_proto.GenerateKeyPairResponse{}, nil
}

func (MemoryPlugin) FetchPrivateKey(*sri_proto.FetchPrivateKeyRequest) (*sri_proto.FetchPrivateKeyResponse, error) {
	return &sri_proto.FetchPrivateKeyResponse{}, nil
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
