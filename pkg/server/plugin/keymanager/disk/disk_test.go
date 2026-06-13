package disk_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager/disk"
	keymanagertest "github.com/spiffe/spire/pkg/server/plugin/keymanager/test"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestKeyManagerContract(t *testing.T) {
	keymanagertest.Test(t, keymanagertest.Config{
		Create: func(t *testing.T) keymanager.KeyManager {
			dir := spiretest.TempDir(t)
			km, err := loadPlugin(t, "keys_path = %q", filepath.Join(dir, "keys.json"))
			require.NoError(t, err)
			return km
		},
	})
}

func TestConfigure(t *testing.T) {
	t.Run("missing keys path", func(t *testing.T) {
		_, err := loadPlugin(t, "")
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "keys_path is required")
	})
}

func TestGenerateKeyBeforeConfigure(t *testing.T) {
	km := new(keymanager.V1)
	plugintest.Load(t, disk.BuiltIn(), km)

	_, err := km.GenerateKey(context.Background(), "id", keymanager.ECP256)
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "keymanager(disk): not configured")
}

func TestGenerateKeyPersistence(t *testing.T) {
	dir := filepath.Join(spiretest.TempDir(t), "no-such-dir")

	km, err := loadPlugin(t, "keys_path = %q", filepath.Join(dir, "keys.json"))
	require.NoError(t, err)

	// assert failure to generate key when directory is gone
	_, err = km.GenerateKey(context.Background(), "id", keymanager.ECP256)
	spiretest.RequireGRPCStatusContains(t, err, codes.Internal, "failed to acquire lock")

	// create the directory and generate the key
	mkdir(t, dir)
	keyIn, err := km.GenerateKey(context.Background(), "id", keymanager.ECP256)
	require.NoError(t, err)

	// reload the plugin. original key should have persisted.
	km, err = loadPlugin(t, "keys_path = %q", filepath.Join(dir, "keys.json"))
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
	spiretest.RequireGRPCStatusContains(t, err, codes.Internal, "failed to acquire lock")

	keyOut, err = km.GetKey(context.Background(), "id")
	require.NoError(t, err)
	require.Equal(t,
		publicKeyBytes(t, keyIn),
		publicKeyBytes(t, keyOut),
	)
}

func TestSharedKeyReuse(t *testing.T) {
	dir := spiretest.TempDir(t)
	keysPath := filepath.Join(dir, "keys.json")
	jwtKeyID := keymanager.JWTSignerKeyIDPrefix + "A"

	configFmt := `
		keys_path = %q
		key_identifier_value = %q
		shared_keys {
			crypto_key_template = "{{ .TrustDomain }}-{{ .KeyID }}"
		}
	`

	km1, err := loadPlugin(t, configFmt, keysPath, "server-a")
	require.NoError(t, err)

	k1, err := km1.GenerateKey(context.Background(), jwtKeyID, keymanager.RSA2048)
	require.NoError(t, err)

	// A second instance sharing the same file should load the JWT key.
	km2, err := loadPlugin(t, configFmt, keysPath, "server-b")
	require.NoError(t, err)

	k2d, err := km2.GetKey(context.Background(), jwtKeyID)
	require.NoError(t, err)
	require.Equal(t, publicKeyBytes(t, k1), publicKeyBytes(t, k2d))

	// Calling GenerateKey again on the second instance should reuse the fresh key.
	k2, err := km2.GenerateKey(context.Background(), jwtKeyID, keymanager.RSA2048)
	require.NoError(t, err)
	require.Equal(t, publicKeyBytes(t, k1), publicKeyBytes(t, k2))

	// Verify the key is stored under the template-derived storage ID.
	fileBytes, err := os.ReadFile(keysPath)
	require.NoError(t, err)
	var fileData struct {
		Keys map[string]struct {
			Id        string    `json:"id"`
			CreatedAt time.Time `json:"created_at"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(fileBytes, &fileData))

	entry, ok := fileData.Keys["example.org-"+jwtKeyID]
	require.True(t, ok, "key should be stored under template-derived ID")
	require.Equal(t, jwtKeyID, entry.Id)
	require.False(t, entry.CreatedAt.IsZero())
}

func TestSharedKeyOnlyJWTKeysAreShared(t *testing.T) {
	dir := spiretest.TempDir(t)
	keysPath := filepath.Join(dir, "keys.json")
	jwtKeyID := keymanager.JWTSignerKeyIDPrefix + "A"
	x509KeyID := keymanager.X509CAKeyIDPrefix + "A"

	configFmt := `
		keys_path = %q
		key_identifier_value = %q
		shared_keys {
			crypto_key_template = "{{ .TrustDomain }}-{{ .KeyID }}"
		}
	`

	kmA, err := loadPlugin(t, configFmt, keysPath, "server-a")
	require.NoError(t, err)
	kmB, err := loadPlugin(t, configFmt, keysPath, "server-b")
	require.NoError(t, err)

	// Both servers generate an X509 CA key and a JWT signing key under the same
	// logical IDs.
	for _, km := range []keymanager.KeyManager{kmA, kmB} {
		_, err := km.GenerateKey(context.Background(), x509KeyID, keymanager.ECP256)
		require.NoError(t, err)
		_, err = km.GenerateKey(context.Background(), jwtKeyID, keymanager.ECP256)
		require.NoError(t, err)
	}

	// The on-disk layout proves the scoping: each server's X509 CA key is stored
	// under a per-server storage slot, while the JWT signing key is stored once
	// under the shared, template-derived slot. (The fake key generator returns
	// deterministic key material, so storage layout — not key bytes — is the
	// reliable signal.)
	storageIDs := readStorageIDs(t, keysPath)
	require.Contains(t, storageIDs, "server-a/"+x509KeyID)
	require.Contains(t, storageIDs, "server-b/"+x509KeyID)
	require.Contains(t, storageIDs, "example.org-"+jwtKeyID)
	require.NotContains(t, storageIDs, "example.org-"+x509KeyID,
		"X509 CA key must not be stored under the shared template slot")

	// Each server only sees its own X509 CA key plus the shared JWT key — never
	// the other server's X509 CA key. This is what keeps the CA journal lookup
	// unambiguous on restart. Simulate a restart of server A with a fresh instance.
	kmARestart, err := loadPlugin(t, configFmt, keysPath, "server-a")
	require.NoError(t, err)

	_, err = kmARestart.GetKey(context.Background(), x509KeyID)
	require.NoError(t, err)
	_, err = kmARestart.GetKey(context.Background(), jwtKeyID)
	require.NoError(t, err)

	keys, err := kmARestart.GetKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 2, "server A should see only its own X509 CA key and the shared JWT key")
}

func readStorageIDs(t *testing.T, keysPath string) map[string]struct{} {
	fileBytes, err := os.ReadFile(keysPath)
	require.NoError(t, err)
	var fileData struct {
		Keys map[string]json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(fileBytes, &fileData))
	ids := make(map[string]struct{}, len(fileData.Keys))
	for id := range fileData.Keys {
		ids[id] = struct{}{}
	}
	return ids
}

func TestSharedKeyRequiresServerIdentifier(t *testing.T) {
	dir := spiretest.TempDir(t)
	keysPath := filepath.Join(dir, "keys.json")

	_, err := loadPlugin(t, `
		keys_path = %q
		shared_keys {
			crypto_key_template = "{{ .TrustDomain }}-{{ .KeyID }}"
		}
	`, keysPath)
	spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument,
		"key_identifier_file or key_identifier_value is required when shared_keys is enabled")
}

func TestSharedKeyLegacyLoad(t *testing.T) {
	dir := spiretest.TempDir(t)
	keysPath := filepath.Join(dir, "keys.json")

	// Write a standard-mode plugin to create a legacy-format keys.json.
	standardFmt := `keys_path = %q`
	kmStd, err := loadPlugin(t, standardFmt, keysPath)
	require.NoError(t, err)

	keyIn, err := kmStd.GenerateKey(context.Background(), "my-key", keymanager.ECP256)
	require.NoError(t, err)

	// Reload in standard mode — should load the legacy file without error.
	kmStd2, err := loadPlugin(t, standardFmt, keysPath)
	require.NoError(t, err)
	keyOut, err := kmStd2.GetKey(context.Background(), "my-key")
	require.NoError(t, err)
	require.Equal(t, publicKeyBytes(t, keyIn), publicKeyBytes(t, keyOut))
}

func TestSharedKeyTemplateCollisionGuard(t *testing.T) {
	dir := spiretest.TempDir(t)
	keysPath := filepath.Join(dir, "keys.json")

	_, err := loadPlugin(t, `
		keys_path = %q
		key_identifier_value = "server-a"
		shared_keys {
			crypto_key_template = "fixed-name"
		}
	`, keysPath)
	spiretest.RequireGRPCStatusContains(t, err, codes.InvalidArgument, "must vary with .KeyID")
}

func TestSharedKeyTypeReuseRejected(t *testing.T) {
	dir := spiretest.TempDir(t)
	keysPath := filepath.Join(dir, "keys.json")

	configFmt := `
		keys_path = %q
		key_identifier_value = "server-a"
		shared_keys {
			crypto_key_template = "{{ .TrustDomain }}-{{ .KeyID }}"
		}
	`
	jwtKeyID := keymanager.JWTSignerKeyIDPrefix + "A"

	km, err := loadPlugin(t, configFmt, keysPath)
	require.NoError(t, err)

	// Generate an RSA-2048 key.
	rsaKey, err := km.GenerateKey(context.Background(), jwtKeyID, keymanager.RSA2048)
	require.NoError(t, err)

	// Reload to pick up the persisted key, then request EC_P256 for the same ID.
	// The fresh RSA key must NOT be reused; a new EC key must be generated.
	km2, err := loadPlugin(t, configFmt, keysPath)
	require.NoError(t, err)

	ecKey, err := km2.GenerateKey(context.Background(), jwtKeyID, keymanager.ECP256)
	require.NoError(t, err)

	// The returned EC public key must differ from the RSA public key.
	require.NotEqual(t, publicKeyBytes(t, rsaKey), publicKeyBytes(t, ecKey),
		"type-mismatched fresh key must not be reused")

	// It must be an EC key, not RSA.
	pkixBytes, err := x509.MarshalPKIXPublicKey(ecKey.Public())
	require.NoError(t, err)
	pub, err := x509.ParsePKIXPublicKey(pkixBytes)
	require.NoError(t, err)
	require.IsType(t, (*ecdsa.PublicKey)(nil), pub,
		"expected ECDSA public key, got %T", pub)
}

func loadPlugin(t *testing.T, configFmt string, configArgs ...any) (keymanager.KeyManager, error) {
	km := new(keymanager.V1)
	var configErr error
	plugintest.Load(t, disk.TestBuiltIn(keymanagertest.NewGenerator()), km,
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
		plugintest.Configuref(configFmt, configArgs...),
		plugintest.CaptureConfigureError(&configErr),
	)
	return km, configErr
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
