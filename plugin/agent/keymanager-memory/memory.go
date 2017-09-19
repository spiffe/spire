package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.com/hashicorp/go-plugin"

	"github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/proto/agent/keymanager"
)

type MemoryPlugin struct {
	key *ecdsa.PrivateKey
}

func (m *MemoryPlugin) GenerateKeyPair(*keymanager.GenerateKeyPairRequest) (key *keymanager.GenerateKeyPairResponse, err error) {
	m.key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	privateKey, err := x509.MarshalECPrivateKey(m.key)
	if err != nil {
		return
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&m.key.PublicKey)
	key = &keymanager.GenerateKeyPairResponse{publicKey, privateKey}
	return
}

func (m *MemoryPlugin) FetchPrivateKey(*keymanager.FetchPrivateKeyRequest) (*keymanager.FetchPrivateKeyResponse, error) {
	if m.key == nil {
		// No key set yet
		return &keymanager.FetchPrivateKeyResponse{[]byte{}}, nil
	}

	privateKey, err := x509.MarshalECPrivateKey(m.key)
	if err != nil {
		return &keymanager.FetchPrivateKeyResponse{[]byte{}}, err
	}

	return &keymanager.FetchPrivateKeyResponse{privateKey}, nil
}

func (m *MemoryPlugin) Configure(*sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	return &sriplugin.ConfigureResponse{}, nil
}

func (m *MemoryPlugin) GetPluginInfo(*sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
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
