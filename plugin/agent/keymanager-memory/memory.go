package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/elliptic"
	"crypto/x509"

	"github.com/hashicorp/go-plugin"

	"github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/agent/keymanager"
)

type MemoryPlugin struct{
	key *ecdsa.PrivateKey
}

func (m *MemoryPlugin) GenerateKeyPair(*keymanager.GenerateKeyPairRequest) (key *keymanager.GenerateKeyPairResponse, err error) {
	m.key,err = ecdsa.GenerateKey(elliptic.P521(),rand.Reader)
	privateKey,err := x509.MarshalECPrivateKey(m.key)
	publicKey, err := x509.MarshalPKIXPublicKey(&m.key.PublicKey)
	key = &keymanager.GenerateKeyPairResponse{publicKey, privateKey}
	return
}

func (m *MemoryPlugin) FetchPrivateKey(*keymanager.FetchPrivateKeyRequest) (key *keymanager.FetchPrivateKeyResponse, err error) {
	privateKey,err := x509.MarshalECPrivateKey(m.key)
	key =&keymanager.FetchPrivateKeyResponse{privateKey}
	return
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
