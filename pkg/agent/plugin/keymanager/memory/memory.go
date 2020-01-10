package memory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"sync"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

const (
	pluginName = "memory"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, keymanager.PluginServer(p))
}

type Plugin struct {
	key *ecdsa.PrivateKey
	mtx sync.RWMutex
}

func New() *Plugin {
	return &Plugin{}
}

func (m *Plugin) GenerateKeyPair(context.Context, *keymanager.GenerateKeyPairRequest) (*keymanager.GenerateKeyPairResponse, error) {
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
	return &keymanager.GenerateKeyPairResponse{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func (m *Plugin) StorePrivateKey(ctx context.Context, req *keymanager.StorePrivateKeyRequest) (*keymanager.StorePrivateKeyResponse, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	key, err := x509.ParseECPrivateKey(req.PrivateKey)
	if err != nil {
		return nil, err
	}
	m.key = key

	return &keymanager.StorePrivateKeyResponse{}, nil
}

func (m *Plugin) FetchPrivateKey(context.Context, *keymanager.FetchPrivateKeyRequest) (*keymanager.FetchPrivateKeyResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

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

func (m *Plugin) Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return &spi.ConfigureResponse{}, nil
}

func (m *Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}
