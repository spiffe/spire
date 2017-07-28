package memory

import (
	"github.com/hashicorp/go-plugin"
	"github.com/spiffe/node-agent/plugins/key_manager"
)

type MemoryPlugin struct{}

func (MemoryPlugin) GenerateKeyPair() (key []byte, err error) {
	return []byte{}, nil
}

func (MemoryPlugin) Configure(configuration string) error {
	return nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: keymanager.Handshake,
		Plugins: map[string]plugin.Plugin{
			"keymanager": keymanager.KeyManagerPlugin{KeyManagerImpl: &MemoryPlugin{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
