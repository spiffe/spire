package memory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"sync"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/plugin/agent/keymanager/v0"
)

const (
	pluginName = "memory"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName, keymanagerv0.KeyManagerPluginServer(p))
}

type Plugin struct {
	keymanagerv0.UnsafeKeyManagerServer

	key *ecdsa.PrivateKey
	mtx sync.RWMutex
}

func New() *Plugin {
	return &Plugin{}
}

func (m *Plugin) GenerateKeyPair(context.Context, *keymanagerv0.GenerateKeyPairRequest) (*keymanagerv0.GenerateKeyPairResponse, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &keymanagerv0.GenerateKeyPairResponse{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func (m *Plugin) StorePrivateKey(ctx context.Context, req *keymanagerv0.StorePrivateKeyRequest) (*keymanagerv0.StorePrivateKeyResponse, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	key, err := x509.ParseECPrivateKey(req.PrivateKey)
	if err != nil {
		return nil, err
	}
	m.key = key

	return &keymanagerv0.StorePrivateKeyResponse{}, nil
}

func (m *Plugin) FetchPrivateKey(context.Context, *keymanagerv0.FetchPrivateKeyRequest) (*keymanagerv0.FetchPrivateKeyResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.key == nil {
		// No key set yet
		return &keymanagerv0.FetchPrivateKeyResponse{PrivateKey: []byte{}}, nil
	}

	privateKey, err := x509.MarshalECPrivateKey(m.key)
	if err != nil {
		return &keymanagerv0.FetchPrivateKeyResponse{PrivateKey: []byte{}}, err
	}

	return &keymanagerv0.FetchPrivateKeyResponse{PrivateKey: privateKey}, nil
}

func (m *Plugin) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (m *Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
