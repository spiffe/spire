package disk

import (
	"context"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire/proto/agent/keymanager"
	spi "github.com/spiffe/spire/proto/common/plugin"
)

var (
	ctx = context.Background()
)

func TestDisk_GenerateKeyPair(t *testing.T) {
	plugin := New()
	tempDir, err := ioutil.TempDir("", "km-disk-test")
	require.NoError(t, err)
	plugin.dir = tempDir
	defer os.RemoveAll(tempDir)

	genResp, err := plugin.GenerateKeyPair(ctx, &keymanager.GenerateKeyPairRequest{})
	require.NoError(t, err)
	_, err = plugin.StorePrivateKey(ctx, &keymanager.StorePrivateKeyRequest{PrivateKey: genResp.PrivateKey})
	require.NoError(t, err)
	_, err = os.Stat(path.Join(tempDir, keyFileName))
	assert.False(t, os.IsNotExist(err))
	assert.NoError(t, err)

	fileData, err := ioutil.ReadFile(path.Join(tempDir, keyFileName))
	assert.NoError(t, err)
	assert.Equal(t, genResp.PrivateKey, fileData)

	_, err = x509.ParseECPrivateKey(genResp.PrivateKey)
	require.NoError(t, err)
}

func TestDisk_FetchPrivateKey(t *testing.T) {
	plugin := New()
	tempDir, err := ioutil.TempDir("", "km-disk-test")
	require.NoError(t, err)
	plugin.dir = tempDir
	defer os.RemoveAll(tempDir)

	genResp, err := plugin.GenerateKeyPair(ctx, &keymanager.GenerateKeyPairRequest{})
	require.NoError(t, err)
	_, err = plugin.StorePrivateKey(ctx, &keymanager.StorePrivateKeyRequest{PrivateKey: genResp.PrivateKey})
	require.NoError(t, err)

	fetchResp, err := plugin.FetchPrivateKey(ctx, &keymanager.FetchPrivateKeyRequest{})
	require.NoError(t, err)
	assert.Equal(t, genResp.PrivateKey, fetchResp.PrivateKey)
}

func TestDisk_Configure(t *testing.T) {
	plugin := New()
	cReq := &spi.ConfigureRequest{
		Configuration: "directory = \"foo/bar\"",
	}
	_, e := plugin.Configure(ctx, cReq)
	assert.NoError(t, e)
	assert.Equal(t, "foo/bar", plugin.dir)
}

func TestDisk_GetPluginInfo(t *testing.T) {
	plugin := New()
	_, e := plugin.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	require.NoError(t, e)
}
