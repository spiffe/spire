package disk_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/disk"
	keymanagertest "github.com/spiffe/spire/pkg/agent/plugin/keymanager/test"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/assert"
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
	spiretest.RequireGRPCStatusContains(t, err, codes.Internal, "failed to write deprecated key")

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
	spiretest.RequireGRPCStatusContains(t, err, codes.Internal, "failed to write deprecated key")

	keyOut, err = km.GetKey(context.Background(), "id")
	require.NoError(t, err)
	require.Equal(t,
		publicKeyBytes(t, keyIn),
		publicKeyBytes(t, keyOut),
	)
}

func TestBackwardsCompatWithDeprecatedKeyFile(t *testing.T) {
	// This test asserts behavior expected on upgrade and downgrade scenarios
	// between the old disk plugin that managed a single key and the new one
	// that conforms to the multi key manager interface. See the comment in
	// the writeEntries and loadEntries methods.

	dir := spiretest.TempDir(t)

	assertKeyEqual := func(expected, actual crypto.Signer) {
		equal, err := cryptoutil.PublicKeyEqual(expected.Public(), actual.Public())
		require.NoError(t, err)
		assert.True(t, equal, "keys are not equal")
	}
	reloadPlugin := func() keymanager.MultiKeyManager {
		km, err := loadPlugin(t, "directory = %q", dir)
		require.NoError(t, err)
		return km
	}
	getPublicKeys := func(km keymanager.MultiKeyManager) map[string]crypto.PublicKey {
		keys, err := km.GetKeys(context.Background())
		require.NoError(t, err)
		publicKeys := make(map[string]crypto.PublicKey)
		for _, key := range keys {
			publicKeys[key.ID()] = key.Public()
		}
		return publicKeys
	}
	deprecatedKeyPath := filepath.Join(dir, "svid.key")

	rotateDeprecatedKey := func() crypto.Signer {
		key := testkey.NewEC256(t)
		data, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		require.NoError(t, ioutil.WriteFile(deprecatedKeyPath, data, 0600))
		return key
	}

	deprecatedKey := rotateDeprecatedKey()

	// Load the plugin
	km := reloadPlugin()

	// Fetch the key by the "deprecated" key ID and assert the keys match
	oldKey, err := km.GetKey(context.Background(), "agent-svid-deprecated")
	require.NoError(t, err)
	assertKeyEqual(deprecatedKey, oldKey)

	// Generate a new key and assert that the deprecated key has been overwritten.
	// Load the key from the deprecated key path and assert it matches the new
	newKey, err := km.GenerateKey(context.Background(), "any-other-id", keymanager.ECP256)
	require.NoError(t, err)
	newDeprecatedKeyData, err := ioutil.ReadFile(deprecatedKeyPath)
	require.NoError(t, err)
	newDeprecatedKey, err := x509.ParseECPrivateKey(newDeprecatedKeyData)
	require.NoError(t, err)
	assertKeyEqual(newKey, newDeprecatedKey)

	// Reload the plugin and assert that there are no entries for the
	// new deprecated key since it matches an existing entry.
	km = reloadPlugin()
	assert.Equal(t, map[string]crypto.PublicKey{
		"any-other-id":          newKey.Public(),
		"agent-svid-deprecated": deprecatedKey.Public(),
	}, getPublicKeys(km))

	// Now overwrite the deprecated key and then reload (simulating what would
	// happen in a downgrade followed by an upgrade).
	downgradedDeprecatedKey := rotateDeprecatedKey()
	km = reloadPlugin()
	assert.Equal(t, map[string]crypto.PublicKey{
		"any-other-id":          newKey.Public(),
		"agent-svid-deprecated": downgradedDeprecatedKey.Public(),
	}, getPublicKeys(km))
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
