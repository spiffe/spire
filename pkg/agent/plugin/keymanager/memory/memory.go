package memory

import (
	"context"
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

func (m *MemoryPlugin) GenerateKeyPair(context.Context, *keymanager.GenerateKeyPairRequest) (key *keymanager.GenerateKeyPairResponse, err error) {
	m.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.MarshalECPrivateKey(m.key)
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&m.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &keymanager.GenerateKeyPairResponse{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func (m *MemoryPlugin) FetchPrivateKey(context.Context, *keymanager.FetchPrivateKeyRequest) (*keymanager.FetchPrivateKeyResponse, error) {
	if m.key == nil {
		// No key set yet
		return &keymanager.FetchPrivateKeyResponse{PrivateKey: []byte{}}, nil
	}

	privateKey, err := x509.MarshalECPrivateKey(m.key)
	if err != nil {
		return &keymanager.FetchPrivateKeyResponse{PrivateKey: []byte{}}, err
	}

	return &keymanager.FetchPrivateKeyResponse{PrivateKey: privateKey}, nil
}

func (m *MemoryPlugin) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (m *MemoryPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func New() *MemoryPlugin {
	return &MemoryPlugin{}
}
