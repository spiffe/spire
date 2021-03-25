package memory

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	keymanagerv0 "github.com/spiffe/spire/proto/spire/agent/keymanager/v0"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

var (
	ctx = context.Background()
)

func TestMemory_GenerateKeyPair(t *testing.T) {
	plugin := New()
	data, e := plugin.GenerateKeyPair(ctx, &keymanagerv0.GenerateKeyPairRequest{})
	require.NoError(t, e)
	_, e = plugin.StorePrivateKey(ctx, &keymanagerv0.StorePrivateKeyRequest{PrivateKey: data.PrivateKey})
	require.NoError(t, e)
	priv, err := x509.ParseECPrivateKey(data.PrivateKey)
	require.NoError(t, err)
	assert.Equal(t, plugin.key, priv)
}

func TestMemory_FetchPrivateKey(t *testing.T) {
	plugin := New()
	data, e := plugin.GenerateKeyPair(ctx, &keymanagerv0.GenerateKeyPairRequest{})
	require.NoError(t, e)
	_, e = plugin.StorePrivateKey(ctx, &keymanagerv0.StorePrivateKeyRequest{PrivateKey: data.PrivateKey})
	require.NoError(t, e)

	priv, e := plugin.FetchPrivateKey(ctx, &keymanagerv0.FetchPrivateKeyRequest{})
	require.NoError(t, e)
	assert.Equal(t, priv.PrivateKey, data.PrivateKey)
}

func TestMemory_Configure(t *testing.T) {
	plugin := New()
	data, e := plugin.Configure(ctx, &spi.ConfigureRequest{})
	require.NoError(t, e)
	assert.Equal(t, &spi.ConfigureResponse{}, data)
}

func TestMemory_GetPluginInfo(t *testing.T) {
	plugin := New()
	data, e := plugin.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	require.NoError(t, e)
	assert.Equal(t, &spi.GetPluginInfoResponse{}, data)
}
