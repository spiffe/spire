package disk_test

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/disk"
	keymanagertest "github.com/spiffe/spire/pkg/agent/plugin/keymanager/test"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestKeyManagerContract(t *testing.T) {
	keymanagertest.Test(t, keymanagertest.Config{
		Create: func(t *testing.T) keymanager.MultiKeyManager {
			dir := spiretest.TempDir(t)
			km, err := loadPlugin(t, "directory = %q", dir)
			require.NoError(t, err)
			return km
		},
	})
}

func TestConfigure(t *testing.T) {
	t.Run("missing directory", func(t *testing.T) {
		_, err := loadPlugin(t, "")
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "directory must be configured")
	})
}

func TestGenerateKeyBeforeConfigure(t *testing.T) {
	km := new(keymanager.V1)
	plugintest.Load(t, disk.BuiltIn(), km)

	_, err := km.GenerateKey(context.Background(), "id", keymanager.ECP256)
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "keymanager(disk): failed to generate key: not configured")
}

func TestGenerateKeyPersistence(t *testing.T) {
	dir := filepath.Join(spiretest.TempDir(t), "no-such-dir")

	km, err := loadPlugin(t, "directory = %q", dir)
	require.NoError(t, err)

	// assert failure to generate key when directory is gone
	_, err = km.GenerateKey(context.Background(), "id", keymanager.ECP256)
	spiretest.RequireGRPCStatusContains(t, err, codes.Internal, "failed to generate key: unable to write entries")

	// create the directory and generate the key
	mkdir(t, dir)
	keyIn, err := km.GenerateKey(context.Background(), "id", keymanager.ECP256)
	require.NoError(t, err)

	// reload the plugin. original key should have persisted.
	km, err = loadPlugin(t, "directory = %q", dir)
	require.NoError(t, err)
	keyOut, err := km.GetKey(context.Background(), "id")
	require.NoError(t, err)
	require.Equal(t,
		publicKeyBytes(t, keyIn),
		publicKeyBytes(t, keyOut),
	)

	// remove the directory and try to overwrite. original key should remain.
	rmdir(t, dir)
	_, err = km.GenerateKey(context.Background(), "id", keymanager.ECP256)
	spiretest.RequireGRPCStatusContains(t, err, codes.Internal, "failed to generate key: unable to write entries")

	keyOut, err = km.GetKey(context.Background(), "id")
	require.NoError(t, err)
	require.Equal(t,
		publicKeyBytes(t, keyIn),
		publicKeyBytes(t, keyOut),
	)
}

func TestDeprecatedKeyFileIsRemovedOnConfigure(t *testing.T) {
	// This test asserts behavior expected on upgrade and downgrade scenarios
	// between the old disk plugin that managed a single key and the new one
	// that conforms to the multi key manager interface. See the comment in
	// the writeEntries and loadEntries methods.

	dir := spiretest.TempDir(t)

	deprecatedKeyPath := filepath.Join(dir, "svid.key")
	err := os.WriteFile(deprecatedKeyPath, nil, 0600)
	require.NoError(t, err)

	_, err = loadPlugin(t, "directory = %q", dir)
	require.NoError(t, err)

	_, err = os.Stat(deprecatedKeyPath)
	require.True(t, errors.Is(err, os.ErrNotExist), "file has not been removed: %v", err)
}

func loadPlugin(t *testing.T, configFmt string, configArgs ...interface{}) (keymanager.MultiKeyManager, error) {
	km := new(keymanager.V1)
	var configErr error
	plugintest.Load(t, disk.BuiltIn(), km,
		plugintest.Configuref(configFmt, configArgs...),
		plugintest.CaptureConfigureError(&configErr),
	)
	multi, ok := km.Multi()
	require.True(t, ok)
	return multi, configErr
}

func mkdir(t *testing.T, dir string) {
	require.NoError(t, os.Mkdir(dir, 0755))
}

func rmdir(t *testing.T, dir string) {
	require.NoError(t, os.RemoveAll(dir))
}

func publicKeyBytes(t *testing.T, key keymanager.Key) []byte {
	b, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	return b
}
