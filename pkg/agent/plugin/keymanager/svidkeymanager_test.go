package keymanager_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/common/catalog"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/plugin/agent/keymanager/v0"
	"github.com/spiffe/spire/test/fakes/fakeagentkeymanager"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSingleSVIDKeyManager(t *testing.T) {
	server := keymanagerv0.KeyManagerPluginServer(&fakeV0Plugin{})
	km := new(keymanager.V0)
	plugintest.Load(t, catalog.MakeBuiltIn("v0test", server), km)

	svidKM := keymanager.ForSVID(km)

	// Assert that there are no keys
	keys, err := svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Generate key (without previous key)
	key, err := svidKM.GenerateKey(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, key.ID())

	// Assert that there are still no keys
	keys, err = svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Set key
	err = svidKM.SetKey(context.Background(), key)
	require.NoError(t, err)

	// Now assert that key is listed
	keys, err = svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []keymanager.Key{key}, keys)

	// Generate new key (passing previous key) and assert the old key is still
	// returned.
	newKey, err := svidKM.GenerateKey(context.Background(), key)
	require.NoError(t, err)

	// Assert that the old key is listed
	keys, err = svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []keymanager.Key{key}, keys)
	assert.NotEqual(t, []keymanager.Key{newKey}, keys)

	// Set new key
	err = svidKM.SetKey(context.Background(), newKey)
	require.NoError(t, err)

	// Now assert that key is listed
	keys, err = svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []keymanager.Key{newKey}, keys)
	assert.NotEqual(t, []keymanager.Key{key}, keys)
}

func TestMultiSVIDKeyManager(t *testing.T) {
	km := fakeagentkeymanager.New(t, "")

	svidKM := keymanager.ForSVID(km)

	// Assert that there are no keys
	keys, err := svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Generate key (without previous key)
	keyA, err := svidKM.GenerateKey(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, "agent-svid-A", keyA.ID(), "key ID does not match the A SVID key ID")

	// Assert that the generated key exists
	keys, err = svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []keymanager.Key{keyA}, keys)

	// Set key
	err = svidKM.SetKey(context.Background(), keyA)
	require.NoError(t, err)

	// Assert A key is still listed (SetKey is a noop)
	keys, err = svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []keymanager.Key{keyA}, keys)

	// Generate B key (passing A key)
	keyB, err := svidKM.GenerateKey(context.Background(), keyA)
	require.NoError(t, err)
	assert.Equal(t, "agent-svid-B", keyB.ID(), "key ID does not match the B SVID key ID")

	// Assert that both keys are listed
	keys, err = svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []keymanager.Key{keyA, keyB}, keys)

	// Set new key
	err = svidKM.SetKey(context.Background(), keyB)
	require.NoError(t, err)

	// Assert that both keys are stille listed (SetKey is a noop)
	keys, err = svidKM.GetKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []keymanager.Key{keyA, keyB}, keys)

	// Regenerate the A key (passing the B key)
	keyA, err = svidKM.GenerateKey(context.Background(), keyB)
	require.NoError(t, err)
	assert.Equal(t, "agent-svid-A", keyA.ID(), "key ID does not match the A SVID key ID")
}

type fakeV0Plugin struct {
	keymanagerv0.UnimplementedKeyManagerServer

	key *ecdsa.PrivateKey
	mtx sync.RWMutex
}

func (m *fakeV0Plugin) GenerateKeyPair(context.Context, *keymanagerv0.GenerateKeyPairRequest) (*keymanagerv0.GenerateKeyPairResponse, error) {
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

func (m *fakeV0Plugin) StorePrivateKey(ctx context.Context, req *keymanagerv0.StorePrivateKeyRequest) (*keymanagerv0.StorePrivateKeyResponse, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	key, err := x509.ParseECPrivateKey(req.PrivateKey)
	if err != nil {
		return nil, err
	}
	m.key = key

	return &keymanagerv0.StorePrivateKeyResponse{}, nil
}

func (m *fakeV0Plugin) FetchPrivateKey(context.Context, *keymanagerv0.FetchPrivateKeyRequest) (*keymanagerv0.FetchPrivateKeyResponse, error) {
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
