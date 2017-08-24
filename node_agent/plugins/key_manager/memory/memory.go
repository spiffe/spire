package main

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/node_agent/plugins/key_manager"
)

type MemoryPlugin struct{}

func (MemoryPlugin) GenerateKeyPair(*keymanager.GenerateKeyPairRequest) (*keymanager.GenerateKeyPairResponse, error) {
	return &keymanager.GenerateKeyPairResponse{}, nil
}

func (MemoryPlugin) FetchPrivateKey(*keymanager.FetchPrivateKeyRequest) (*keymanager.FetchPrivateKeyResponse, error) {
	return &keymanager.FetchPrivateKeyResponse{}, nil
}

func (MemoryPlugin) Configure(*sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return &sriplugin.ConfigureResponse{}, nil
}

func (MemoryPlugin) GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return &sriplugin.GetPluginInfoResponse{}, nil
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
