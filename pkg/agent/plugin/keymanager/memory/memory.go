package memory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.com/spiffe/spire/proto/agent/keymanager"
	spi "github.com/spiffe/spire/proto/common/plugin"
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

func (m *MemoryPlugin) Configure(*spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (m *MemoryPlugin) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func New() *MemoryPlugin {
	return &MemoryPlugin{}
}
