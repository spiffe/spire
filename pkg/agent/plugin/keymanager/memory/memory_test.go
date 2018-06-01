package memory

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/proto/agent/keymanager"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

var (
	ctx = context.Background()
)

func TestMemory_GenerateKeyPair(t *testing.T) {
	plugin := New()
	data, e := plugin.GenerateKeyPair(ctx, &keymanager.GenerateKeyPairRequest{})
	require.NoError(t, e)
	priv, err := x509.ParseECPrivateKey(data.PrivateKey)
	require.NoError(t, err)
	assert.Equal(t, plugin.key, priv)
}

func TestMemory_FetchPrivateKey(t *testing.T) {
	plugin := New()
	data, e := plugin.GenerateKeyPair(ctx, &keymanager.GenerateKeyPairRequest{})
	require.NoError(t, e)

	priv, e := plugin.FetchPrivateKey(ctx, &keymanager.FetchPrivateKeyRequest{})
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
