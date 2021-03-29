package disk

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	keymanagerv0 "github.com/spiffe/spire/proto/spire/plugin/agent/keymanager/v0"
	"github.com/spiffe/spire/test/spiretest"
)

var (
	ctx = context.Background()
)

func TestDisk_GenerateKeyPair(t *testing.T) {
	tempDir := spiretest.TempDir(t)

	plugin := New()
	plugin.dir = tempDir

	genResp, err := plugin.GenerateKeyPair(ctx, &keymanagerv0.GenerateKeyPairRequest{})
	require.NoError(t, err)
	_, err = plugin.StorePrivateKey(ctx, &keymanagerv0.StorePrivateKeyRequest{PrivateKey: genResp.PrivateKey})
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
	tempDir := spiretest.TempDir(t)

	plugin := New()
	plugin.dir = tempDir

	genResp, err := plugin.GenerateKeyPair(ctx, &keymanagerv0.GenerateKeyPairRequest{})
	require.NoError(t, err)
	_, err = plugin.StorePrivateKey(ctx, &keymanagerv0.StorePrivateKeyRequest{PrivateKey: genResp.PrivateKey})
	require.NoError(t, err)

	fetchResp, err := plugin.FetchPrivateKey(ctx, &keymanagerv0.FetchPrivateKeyRequest{})
	require.NoError(t, err)
	assert.Equal(t, genResp.PrivateKey, fetchResp.PrivateKey)
}

func TestDisk_Configure(t *testing.T) {
	tempDir := spiretest.TempDir(t)
	keysDir := filepath.Join(tempDir, "keys")

	plugin := New()
	cReq := &spi.ConfigureRequest{
		Configuration: fmt.Sprintf("directory = \"%s\"", keysDir),
	}
	_, e := plugin.Configure(ctx, cReq)
	assert.NoError(t, e)
	assert.Equal(t, keysDir, plugin.dir)
	assert.DirExists(t, keysDir)
}

func TestDisk_Configure_DirectoryIsRequired(t *testing.T) {
	expectedErr := errors.New("directory is required")

	plugin := New()
	cReq := &spi.ConfigureRequest{
		Configuration: fmt.Sprintf("directory = \"%s\"", ""),
	}
	_, e := plugin.Configure(ctx, cReq)
	assert.NotNil(t, e)
	assert.Equal(t, expectedErr, e)
}

func TestDisk_GetPluginInfo(t *testing.T) {
	plugin := New()
	_, e := plugin.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	require.NoError(t, e)
}
