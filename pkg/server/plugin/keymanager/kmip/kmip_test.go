package kmip

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	ovh "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/kmiptest"
	"github.com/ovh/kmip-go/payloads"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	testServerID    = "test-server-0001"
	testTrustDomain = "example.org"
)

// ─── Configure ───────────────────────────────────────────────────────────────

func TestConfigure(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	caFile := writeTempPEM(t, caPEM)

	for _, tt := range []struct {
		name       string
		config     string
		expectCode codes.Code
		expectMsg  string
	}{
		{
			name: "valid config",
			config: fmt.Sprintf(`
				kmip_addr            = %q
				ca_cert_path         = %q
				server_id_value      = %q
				insecure_skip_verify = true
			`, addr, caFile, testServerID),
			expectCode: codes.OK,
		},
		{
			name: "valid config with minimum stale key threshold",
			config: fmt.Sprintf(`
				kmip_addr            = %q
				ca_cert_path         = %q
				server_id_value      = %q
				insecure_skip_verify = true
				stale_key_threshold  = "24h"
			`, addr, caFile, testServerID),
			expectCode: codes.OK,
		},
		{
			name:       "missing kmip_addr",
			config:     fmt.Sprintf(`server_id_value = %q insecure_skip_verify = true`, testServerID),
			expectCode: codes.InvalidArgument,
			expectMsg:  "kmip_addr",
		},
		{
			name:       "missing server_id",
			config:     fmt.Sprintf(`kmip_addr = %q insecure_skip_verify = true`, addr),
			expectCode: codes.InvalidArgument,
			expectMsg:  "server_id",
		},
		{
			name: "server_id value and file both set",
			config: fmt.Sprintf(`
				kmip_addr            = %q
				server_id_value      = %q
				server_id_file       = "server-id-file"
				insecure_skip_verify = true
			`, addr, testServerID),
			expectCode: codes.InvalidArgument,
			expectMsg:  "server_id_value and server_id_file",
		},
		{
			name: "key path set but no cert path",
			config: fmt.Sprintf(`
				kmip_addr            = %q
				server_id_value      = %q
				client_key_path      = "some.key"
				insecure_skip_verify = true
			`, addr, testServerID),
			expectCode: codes.InvalidArgument,
			expectMsg:  "client_cert_path",
		},
		{
			name: "invalid stale key threshold",
			config: fmt.Sprintf(`
				kmip_addr            = %q
				server_id_value      = %q
				insecure_skip_verify = true
				stale_key_threshold  = "not-a-duration"
			`, addr, testServerID),
			expectCode: codes.InvalidArgument,
			expectMsg:  "unable to parse stale_key_threshold",
		},
		{
			name: "stale key threshold below minimum",
			config: fmt.Sprintf(`
				kmip_addr            = %q
				server_id_value      = %q
				insecure_skip_verify = true
				stale_key_threshold  = "23h"
			`, addr, testServerID),
			expectCode: codes.InvalidArgument,
			expectMsg:  "stale_key_threshold must be at least 24h0m0s",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			var configErr error
			plugintest.Load(t, builtin(p), nil,
				plugintest.CaptureConfigureError(&configErr),
				plugintest.Configure(tt.config),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString(testTrustDomain),
				}),
			)
			spiretest.RequireGRPCStatusHasPrefix(t, configErr, tt.expectCode, tt.expectMsg)
		})
	}
}

func TestConfigureClosesPreviousClient(t *testing.T) {
	store := newFakeStore()
	closed := make(chan struct{}, 1)
	addr, caPEM, srv := kmiptest.NewServerWithHandle(t, store.handler())
	srv.WithTerminateHook(func(context.Context) {
		select {
		case closed <- struct{}{}:
		default:
		}
	})
	caFile := writeTempPEM(t, caPEM)

	p := New()
	p.SetLogger(hclog.NewNullLogger())
	p.clk = clock.NewMock()
	t.Cleanup(func() {
		if p.cancelTasks != nil {
			p.cancelTasks()
		}
	})

	req := &configv1.ConfigureRequest{
		HclConfiguration: fmt.Sprintf(`
			kmip_addr            = %q
			ca_cert_path         = %q
			insecure_skip_verify = true
			server_id_value      = %q
		`, addr, caFile, testServerID),
		CoreConfiguration: &configv1.CoreConfiguration{
			TrustDomain: testTrustDomain,
		},
	}

	_, err := p.Configure(context.Background(), req)
	require.NoError(t, err)
	require.Empty(t, closed, "initial configure must not close a connection")

	_, err = p.Configure(context.Background(), req)
	require.NoError(t, err)

	// Reconfiguring must close the previous client's connection.
	require.Eventually(t, func() bool {
		select {
		case <-closed:
			return true
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond)
}

func TestConfigureReconfigures(t *testing.T) {
	store1 := newFakeStore()
	addr1, caPEM1 := kmiptest.NewServer(t, store1.handler())
	store2 := newFakeStore()
	addr2, caPEM2 := kmiptest.NewServer(t, store2.handler())
	caFile1 := writeTempPEM(t, caPEM1)
	caFile2 := writeTempPEM(t, caPEM2)

	p := New()
	p.SetLogger(hclog.NewNullLogger())
	p.clk = clock.NewMock()
	t.Cleanup(func() {
		if p.cancelTasks != nil {
			p.cancelTasks()
		}
	})

	makeReq := func(addr, caFile, serverID string) *configv1.ConfigureRequest {
		return &configv1.ConfigureRequest{
			HclConfiguration: fmt.Sprintf(`
				kmip_addr            = %q
				ca_cert_path         = %q
				insecure_skip_verify = true
				server_id_value      = %q
			`, addr, caFile, serverID),
			CoreConfiguration: &configv1.CoreConfiguration{
				TrustDomain: testTrustDomain,
			},
		}
	}

	_, err := p.Configure(context.Background(), makeReq(addr1, caFile1, "server-a"))
	require.NoError(t, err)
	require.Equal(t, "server-a", p.serverID)

	// Reconfigure against a different server and server ID.
	_, err = p.Configure(context.Background(), makeReq(addr2, caFile2, "server-b"))
	require.NoError(t, err)
	require.Equal(t, "server-b", p.serverID)

	// The plugin must now talk to the second server: a new key lands in store2.
	resp, err := p.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   "k1",
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	store1.mu.Lock()
	require.Empty(t, store1.keys, "first server must not receive the key")
	store1.mu.Unlock()

	store2.mu.Lock()
	require.NotEmpty(t, store2.keys, "second server must receive the key")
	store2.mu.Unlock()
}

func TestGetOrCreateServerID(t *testing.T) {
	t.Run("creates a new ID when the file does not exist", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "server-id")
		id, err := getOrCreateServerID(path)
		require.NoError(t, err)
		require.NotEmpty(t, id)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, id, string(data))
	})

	t.Run("reuses the existing ID", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "server-id")
		first, err := getOrCreateServerID(path)
		require.NoError(t, err)

		second, err := getOrCreateServerID(path)
		require.NoError(t, err)
		require.Equal(t, first, second)
	})

	t.Run("rejects an invalid ID", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "server-id")
		require.NoError(t, os.WriteFile(path, []byte("not-a-uuid"), 0o600))

		_, err := getOrCreateServerID(path)
		require.Error(t, err)
	})
}

// ─── GenerateKey ─────────────────────────────────────────────────────────────

func TestGenerateKey(t *testing.T) {
	for _, tt := range []struct {
		name    string
		keyType keymanager.KeyType
	}{
		{"EC_P256", keymanager.ECP256},
		{"EC_P384", keymanager.ECP384},
		{"RSA_2048", keymanager.RSA2048},
		// RSA_4096 omitted to keep the test fast.
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newFakeStore()
			addr, caPEM := kmiptest.NewServer(t, store.handler())
			km := loadPlugin(t, addr, caPEM)

			key, err := km.GenerateKey(context.Background(), "spire-key-"+tt.name, tt.keyType)
			require.NoError(t, err)
			require.NotNil(t, key.Public())
		})
	}
}

func TestGenerateKeySameID(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	p, clk := newTestPlugin(t, addr, caPEM)

	first, err := p.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   "spire-key",
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	require.NoError(t, err)
	oldUID := entryPrivateKeyUID(t, p, "spire-key")

	second, err := p.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   "spire-key",
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	require.NoError(t, err)
	newUID := entryPrivateKeyUID(t, p, "spire-key")

	require.NotEqual(t, first.PublicKey.Fingerprint, second.PublicKey.Fingerprint, "rotation must produce a new key")
	require.NotEqual(t, oldUID, newUID, "rotation must replace the tracked private key")

	// The replacement key must be usable for signing.
	digest := sha256.Sum256([]byte("rotate"))
	signResp, err := p.SignData(context.Background(), &keymanagerv1.SignDataRequest{
		KeyId: "spire-key",
		Data:  digest[:],
		SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, signResp.Signature)

	// Rotation intentionally leaves the old key in KMIP until the stale-key
	// reclamation task reaps it later.
	store.mu.Lock()
	require.Contains(t, store.keys, oldUID, "old key should still exist immediately after rotation")
	require.Contains(t, store.keys, newUID, "replacement key should exist immediately after rotation")
	require.False(t, store.revoked[oldUID], "old key should not be revoked immediately on rotation")
	store.mu.Unlock()

	setPrivateKeyLastUpdate(t, store, oldUID, clk.Now().Add(-p.staleKeyThreshold-time.Second).Unix())
	require.NoError(t, p.disposeStaleKeys(context.Background()))

	store.mu.Lock()
	require.NotContains(t, store.keys, oldUID, "old key should be reclaimed once it becomes stale")
	require.Contains(t, store.keys, newUID, "replacement key should remain after stale-key reclamation")
	require.True(t, store.revoked[oldUID], "stale rotated key should be revoked before destruction")
	store.mu.Unlock()
	require.Equal(t, newUID, entryPrivateKeyUID(t, p, "spire-key"))
}

func TestGenerateKeyNotConfigured(t *testing.T) {
	p := New()
	_, err := p.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   "k1",
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "plugin not configured")
}

func TestGenerateKeyMissingKeyID(t *testing.T) {
	p := New()
	_, err := p.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "key id is required")
}

// ─── SignData ─────────────────────────────────────────────────────────────────

func TestSignData(t *testing.T) {
	for _, tt := range []struct {
		name    string
		keyType keymanager.KeyType
	}{
		{"EC_P256", keymanager.ECP256},
		{"EC_P384", keymanager.ECP384},
		{"RSA_2048", keymanager.RSA2048},
		// RSA_4096 omitted to keep the test fast.
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newFakeStore()
			addr, caPEM := kmiptest.NewServer(t, store.handler())
			km := loadPlugin(t, addr, caPEM)

			key, err := km.GenerateKey(context.Background(), "sign-key", tt.keyType)
			require.NoError(t, err)

			digest := sha256.Sum256([]byte("hello spire"))
			sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
			require.NoError(t, err)
			require.NotEmpty(t, sig)

			// Verify the signature against the public key, using the algorithm
			// appropriate for the key type.
			switch pub := key.Public().(type) {
			case *ecdsa.PublicKey:
				require.True(t, ecdsa.VerifyASN1(pub, digest[:], sig))
			case *rsa.PublicKey:
				require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig))
			default:
				t.Fatalf("unexpected public key type %T", key.Public())
			}
		})
	}
}

func TestSignDataPSSCryptographicParameters(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	km := loadPlugin(t, addr, caPEM)

	key, err := km.GenerateKey(context.Background(), "sign-key", keymanager.RSA2048)
	require.NoError(t, err)

	digest := sha512.Sum384([]byte("hello spire"))
	opts := &rsa.PSSOptions{
		SaltLength: 48,
		Hash:       crypto.SHA384,
	}

	sig, err := key.Sign(rand.Reader, digest[:], opts)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	pub, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok)
	require.NoError(t, rsa.VerifyPSS(pub, crypto.SHA384, digest[:], sig, opts))

	store.mu.Lock()
	signReq := store.lastSignRequest
	store.mu.Unlock()
	require.NotNil(t, signReq)
	require.NotNil(t, signReq.CryptographicParameters)
	require.Equal(t, ovh.DigitalSignatureAlgorithmRSASSA_PSS, signReq.CryptographicParameters.DigitalSignatureAlgorithm)
	require.Equal(t, ovh.HashingAlgorithmSHA_384, signReq.CryptographicParameters.HashingAlgorithm)
	require.Equal(t, ovh.MaskGeneratorMGF1, signReq.CryptographicParameters.MaskGenerator)
	require.Equal(t, ovh.HashingAlgorithmSHA_384, signReq.CryptographicParameters.MaskGeneratorHashingAlgorithm)
	require.NotNil(t, signReq.CryptographicParameters.SaltLength)
	require.EqualValues(t, opts.SaltLength, *signReq.CryptographicParameters.SaltLength)
}

func TestSignDataKeyNotFound(t *testing.T) {
	p := New()
	_, err := p.SignData(context.Background(), &keymanagerv1.SignDataRequest{
		KeyId: "does-not-exist",
		Data:  []byte("x"),
		SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
		},
	})
	spiretest.RequireGRPCStatus(t, err, codes.FailedPrecondition, "plugin not configured")
}

// ─── GetPublicKeys ────────────────────────────────────────────────────────────

func TestGetPublicKeys(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	km := loadPlugin(t, addr, caPEM)

	for _, id := range []string{"k1", "k2"} {
		_, err := km.GenerateKey(context.Background(), id, keymanager.ECP256)
		require.NoError(t, err)
	}

	keys, err := km.GetKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 2)
}

// ─── Key recovery ─────────────────────────────────────────────────────────────

func TestKeyRecovery(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())

	km1 := loadPlugin(t, addr, caPEM)
	_, err := km1.GenerateKey(context.Background(), "recovery-key", keymanager.ECP256)
	require.NoError(t, err)

	// Second plugin instance must recover the key via Locate on Configure.
	km2 := loadPlugin(t, addr, caPEM)
	key, err := km2.GetKey(context.Background(), "recovery-key")
	require.NoError(t, err)
	require.NotNil(t, key.Public())
}

// TestGenerateKeyRotationMarksExactlyOneActiveKey reproduces the scenario flagged
// in review: SPIRE reuses key IDs across rotations, so after GenerateKey is called
// twice with the same KeyId, two key objects sharing that spire-key-id exist on the
// KMIP server simultaneously (the old one isn't destroyed until the reclamation
// task's stale-key threshold elapses). Exactly one of them must be marked
// spire-active:true at all times so recovery is unambiguous.
func TestGenerateKeyRotationMarksExactlyOneActiveKey(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	p, _ := newTestPlugin(t, addr, caPEM)

	ctx := context.Background()
	_, err := p.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{KeyId: "rotate-key", KeyType: keymanagerv1.KeyType_EC_P256})
	require.NoError(t, err)
	oldUID := entryPrivateKeyUID(t, p, "rotate-key")

	_, err = p.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{KeyId: "rotate-key", KeyType: keymanagerv1.KeyType_EC_P256})
	require.NoError(t, err)
	newUID := entryPrivateKeyUID(t, p, "rotate-key")
	require.NotEqual(t, oldUID, newUID, "rotation must create a new key object")

	store.mu.Lock()
	defer store.mu.Unlock()
	require.NotContains(t, store.keys[oldUID].nameAttrs, activeNameValue(), "superseded key must have its active marker cleared")
	require.Contains(t, store.keys[newUID].nameAttrs, activeNameValue(), "the newly generated key must be marked active")
}

// TestKeyRecoveryAfterRotationPicksActiveKey reproduces the ambiguity flagged in
// review end-to-end: after a rotation, both the old and new key objects for
// "rotate-key" still exist on the KMIP server (the old one is only reclaimed later
// by the stale-key disposal task). A fresh plugin instance recovering keys via
// Locate must pick the new, active key rather than whichever object Locate happens
// to return.
func TestKeyRecoveryAfterRotationPicksActiveKey(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	p1, _ := newTestPlugin(t, addr, caPEM)

	ctx := context.Background()
	_, err := p1.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{KeyId: "rotate-key", KeyType: keymanagerv1.KeyType_EC_P256})
	require.NoError(t, err)
	rotatedPK, err := p1.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{KeyId: "rotate-key", KeyType: keymanagerv1.KeyType_EC_P256})
	require.NoError(t, err)

	// A new plugin instance recovers keys from scratch via Locate.
	p2, _ := newTestPlugin(t, addr, caPEM)
	recovered, err := p2.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{KeyId: "rotate-key"})
	require.NoError(t, err)
	require.Equal(t, rotatedPK.PublicKey.Fingerprint, recovered.PublicKey.Fingerprint,
		"recovery must pick the active (post-rotation) key, not an arbitrary one sharing the same spire-key-id")
}

// TestKeyRecoveryFallsBackToFreshestWhenActiveMarkerAmbiguous covers the narrow
// crash window where a rotation created a new active key but a crash prevented
// clearing the marker on the key it supersedes, leaving two key objects for the
// same spire-key-id both marked active. Recovery must not error out; it falls back
// to the one with the newest spire-last-update timestamp.
func TestKeyRecoveryFallsBackToFreshestWhenActiveMarkerAmbiguous(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())

	now := time.Unix(1_700_000_000, 0)
	store.seed("old-priv", "old-pub", []string{
		serverIDNameValue(testServerID),
		trustDomainNameValue(testTrustDomain),
		prefixKeyID + "ambiguous-key",
		prefixKeyType + "EC_P256",
		lastUpdateNameValue(now.Add(-time.Hour).Unix()),
		activeNameValue(),
	})
	store.seed("new-priv", "new-pub", []string{
		serverIDNameValue(testServerID),
		trustDomainNameValue(testTrustDomain),
		prefixKeyID + "ambiguous-key",
		prefixKeyType + "EC_P256",
		lastUpdateNameValue(now.Unix()),
		activeNameValue(),
	})
	seedECKeyMaterial(t, store, "old-priv", "old-pub")
	seedECKeyMaterial(t, store, "new-priv", "new-pub")

	p, _ := newTestPlugin(t, addr, caPEM)
	require.Equal(t, "new-priv", entryPrivateKeyUID(t, p, "ambiguous-key"))
}

// ─── Key reclamation ─────────────────────────────────────────────────────────

func TestGenerateKeyTagsAtCreation(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	km := loadPlugin(t, addr, caPEM)

	_, err := km.GenerateKey(context.Background(), "tagged-key", keymanager.ECP256)
	require.NoError(t, err)

	store.mu.Lock()
	defer store.mu.Unlock()
	require.Len(t, store.keys, 1)
	for _, rec := range store.keys {
		require.Contains(t, rec.nameAttrs, serverIDNameValue(testServerID))
		require.Contains(t, rec.nameAttrs, trustDomainNameValue(testTrustDomain))
		require.Contains(t, rec.nameAttrs, prefixKeyID+"tagged-key")
		require.Contains(t, rec.nameAttrs, prefixKeyType+"EC_P256")
		require.NotEmpty(t, prefixValue(rec.nameAttrs, prefixLastUpdate))
	}
}

func TestKeepKeysActive(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	p, clk := newTestPlugin(t, addr, caPEM)

	_, err := p.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   "active-key",
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	require.NoError(t, err)

	oldTS := readLastUpdate(t, store)

	clk.Add(time.Hour)
	require.NoError(t, p.keepKeysActive(context.Background()))

	newTS := readLastUpdate(t, store)
	require.NotEqual(t, oldTS, newTS)
	require.Equal(t, clk.Now().Unix(), newTS)
}

func TestDisposeStaleKeys(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	p, clk := newTestPlugin(t, addr, caPEM)

	now := clk.Now()
	store.seed("stale-priv", "stale-pub", []string{
		serverIDNameValue(testServerID),
		lastUpdateNameValue(now.Add(-30 * 24 * time.Hour).Unix()),
	})
	store.seed("fresh-priv", "fresh-pub", []string{
		serverIDNameValue(testServerID),
		lastUpdateNameValue(now.Unix()),
	})
	p.mu.Lock()
	p.entries["stale-key"] = keyEntry{
		privateKeyUID: "stale-priv",
		publicKey:     &keymanagerv1.PublicKey{Id: "stale-key", Type: keymanagerv1.KeyType_EC_P256},
	}
	p.entries["fresh-key"] = keyEntry{
		privateKeyUID: "fresh-priv",
		publicKey:     &keymanagerv1.PublicKey{Id: "fresh-key", Type: keymanagerv1.KeyType_EC_P256},
	}
	p.mu.Unlock()

	require.NoError(t, p.disposeStaleKeys(context.Background()))

	store.mu.Lock()
	require.NotContains(t, store.keys, "stale-priv", "stale key should be disposed")
	require.Contains(t, store.keys, "fresh-priv", "fresh key should be kept")
	require.True(t, store.revoked["stale-priv"], "stale key should be revoked before being destroyed")
	require.False(t, store.revoked["fresh-priv"], "fresh key should not be revoked")
	// The stale key's public key must be destroyed too, and the fresh key's public
	// key must be kept — the pair is never leaked or removed too soon.
	require.NotContains(t, store.pubKeys, "stale-pub", "stale public key should be disposed with its private key")
	require.Contains(t, store.pubKeys, "fresh-pub", "fresh public key should be kept")
	store.mu.Unlock()

	p.mu.RLock()
	defer p.mu.RUnlock()
	require.NotContains(t, p.entries, "stale-key", "disposed stale key should be removed from the in-memory index")
	require.Contains(t, p.entries, "fresh-key", "entries for non-disposed keys should be kept")
}

func TestDisposeStaleKeysIgnoresStalePublicKey(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	p, clk := newTestPlugin(t, addr, caPEM)

	now := clk.Now()
	// The private key is still active (fresh last-update), but its public key's
	// last-update has gone stale. The reclaimer must not reap the public key.
	store.seedPair("active-priv", "active-pub",
		[]string{
			serverIDNameValue(testServerID),
			lastUpdateNameValue(now.Unix()),
		},
		[]string{
			serverIDNameValue(testServerID),
			lastUpdateNameValue(now.Add(-30 * 24 * time.Hour).Unix()),
		},
	)

	require.NoError(t, p.disposeStaleKeys(context.Background()))

	store.mu.Lock()
	defer store.mu.Unlock()
	require.Contains(t, store.keys, "active-priv", "active private key should be kept")
	require.Contains(t, store.pubKeys, "active-pub", "stale public key must not be reaped")
}

func TestDisposeStaleKeysPaginates(t *testing.T) {
	store := newFakeStore()
	addr, caPEM := kmiptest.NewServer(t, store.handler())
	p, clk := newTestPlugin(t, addr, caPEM)

	now := clk.Now()
	// Seed more keys than the page size so disposal must paginate through the
	// Locate results.
	const keyCount = 5
	for i := range keyCount {
		store.seed(
			fmt.Sprintf("stale-priv-%d", i),
			fmt.Sprintf("stale-pub-%d", i),
			[]string{
				serverIDNameValue(testServerID),
				lastUpdateNameValue(now.Add(-30 * 24 * time.Hour).Unix()),
			},
		)
	}

	oldPageSize := locatePageSize
	locatePageSize = 2
	defer func() { locatePageSize = oldPageSize }()

	require.NoError(t, p.disposeStaleKeys(context.Background()))

	store.mu.Lock()
	defer store.mu.Unlock()
	require.Empty(t, store.keys, "all stale keys should be disposed across pages")
}

func TestDisposeStaleKeysUsesConfiguredStaleKeyThreshold(t *testing.T) {
	for _, tt := range []struct {
		name        string
		extraConfig string
		threshold   time.Duration
		staleAge    time.Duration
		freshAge    time.Duration
	}{
		{
			name:      "defaults to two weeks when omitted",
			threshold: defaultStaleKeyThreshold,
			staleAge:  defaultStaleKeyThreshold + time.Hour,
			freshAge:  defaultStaleKeyThreshold - time.Hour,
		},
		{
			name:        "uses configured threshold",
			extraConfig: `stale_key_threshold = "24h"`,
			threshold:   minStaleKeyThreshold,
			staleAge:    minStaleKeyThreshold + time.Hour,
			freshAge:    minStaleKeyThreshold - time.Hour,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newFakeStore()
			addr, caPEM := kmiptest.NewServer(t, store.handler())
			p, clk := newTestPluginWithConfig(t, addr, caPEM, tt.extraConfig)

			now := clk.Now()
			store.seed("stale-priv", "stale-pub", []string{
				serverIDNameValue(testServerID),
				lastUpdateNameValue(now.Add(-tt.staleAge).Unix()),
			})
			store.seed("fresh-priv", "fresh-pub", []string{
				serverIDNameValue(testServerID),
				lastUpdateNameValue(now.Add(-tt.freshAge).Unix()),
			})

			require.Equal(t, tt.threshold, p.staleKeyThreshold)
			require.NoError(t, p.disposeStaleKeys(context.Background()))

			store.mu.Lock()
			defer store.mu.Unlock()
			require.NotContains(t, store.keys, "stale-priv", "key older than the threshold should be disposed")
			require.Contains(t, store.keys, "fresh-priv", "key newer than the threshold should be kept")
		})
	}
}

// ─── test helpers ─────────────────────────────────────────────────────────────

func loadPlugin(t *testing.T, addr, caPEM string) *keymanager.V1 {
	t.Helper()
	caFile := writeTempPEM(t, caPEM)
	p := New()
	v1 := new(keymanager.V1)
	plugintest.Load(t, builtin(p), v1,
		plugintest.Configure(fmt.Sprintf(`
			kmip_addr            = %q
			ca_cert_path         = %q
			insecure_skip_verify = true
			server_id_value      = %q
		`, addr, caFile, testServerID)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString(testTrustDomain),
		}),
	)
	return v1
}

func writeTempPEM(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.pem")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// newTestPlugin configures a Plugin against the test KMIP server using a mock
// clock, so tests can control the passage of time for the reclamation tasks.
func newTestPlugin(t *testing.T, addr, caPEM string) (*Plugin, *clock.Mock) {
	t.Helper()
	return newTestPluginWithConfig(t, addr, caPEM, "")
}

func newTestPluginWithConfig(t *testing.T, addr, caPEM, extraConfig string) (*Plugin, *clock.Mock) {
	t.Helper()
	caFile := writeTempPEM(t, caPEM)
	p := New()
	clk := clock.NewMock()
	clk.Set(time.Unix(1_700_000_000, 0))
	p.clk = clk

	var configErr error
	plugintest.Load(t, builtin(p), nil,
		plugintest.CaptureConfigureError(&configErr),
		plugintest.Configure(fmt.Sprintf(`
			kmip_addr            = %q
			ca_cert_path         = %q
			insecure_skip_verify = true
			server_id_value      = %q
			%s
		`, addr, caFile, testServerID, extraConfig)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString(testTrustDomain),
		}),
	)
	require.NoError(t, configErr)
	return p, clk
}

// seedECKeyMaterial attaches real EC P-256 key material to a key record
// previously inserted with fakeStore.seed/seedPair, so recovery's Get() call for
// the public key succeeds.
func seedECKeyMaterial(t *testing.T, store *fakeStore, privUID, pubUID string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pkix, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	store.mu.Lock()
	defer store.mu.Unlock()
	rec, ok := store.keys[privUID]
	require.True(t, ok, "expected private key %q to exist", privUID)
	rec.privKey = priv
	rec.pubPKIX = pkix
	_ = pubUID
}

func entryPrivateKeyUID(t *testing.T, p *Plugin, keyID string) string {
	t.Helper()
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.entries[keyID]
	require.True(t, ok, "expected entry %q to exist", keyID)
	return entry.privateKeyUID
}

func setPrivateKeyLastUpdate(t *testing.T, store *fakeStore, privUID string, ts int64) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	rec, ok := store.keys[privUID]
	require.True(t, ok, "expected private key %q to exist", privUID)
	for i, nameAttr := range rec.nameAttrs {
		if strings.HasPrefix(nameAttr, prefixLastUpdate) {
			rec.nameAttrs[i] = lastUpdateNameValue(ts)
			return
		}
	}
	rec.nameAttrs = append(rec.nameAttrs, lastUpdateNameValue(ts))
}

// readLastUpdate returns the spire-last-update timestamp of the single key in the
// store.
func readLastUpdate(t *testing.T, store *fakeStore) int64 {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, rec := range store.keys {
		ts, err := strconv.ParseInt(prefixValue(rec.nameAttrs, prefixLastUpdate), 10, 64)
		require.NoError(t, err)
		return ts
	}
	require.FailNow(t, "no keys in store")
	return 0
}

// ─── fakeStore ── in-memory KMIP server ──────────────────────────────────────

type keyRecord struct {
	privUID      string
	pubUID       string
	privKey      crypto.Signer
	pubPKIX      []byte
	nameAttrs    []string // private-key Name attributes
	pubNameAttrs []string // public-key Name attributes
}

type fakeStore struct {
	mu              sync.Mutex
	keys            map[string]*keyRecord // privUID → record
	pubKeys         map[string]*keyRecord // pubUID → record
	revoked         map[string]bool       // uid → revoked via the Revoke operation
	lastSignRequest *payloads.SignRequestPayload
	counter         int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		keys:    make(map[string]*keyRecord),
		pubKeys: make(map[string]*keyRecord),
		revoked: make(map[string]bool),
	}
}

func (s *fakeStore) nextUID(prefix string) string {
	s.counter++
	return fmt.Sprintf("%s-%04d", prefix, s.counter)
}

// seed inserts a key record with the given name attributes applied to both the
// private and public key directly into the store.
func (s *fakeStore) seed(privUID, pubUID string, nameAttrs []string) {
	s.seedPair(privUID, pubUID, nameAttrs, nameAttrs)
}

// seedPair inserts a key record whose private and public keys carry distinct
// Name attributes, matching the real KMIP server where the two keys are separate
// objects that can be tagged independently.
func (s *fakeStore) seedPair(privUID, pubUID string, privNameAttrs, pubNameAttrs []string) {
	rec := &keyRecord{
		privUID:      privUID,
		pubUID:       pubUID,
		nameAttrs:    privNameAttrs,
		pubNameAttrs: pubNameAttrs,
	}
	s.keys[privUID] = rec
	s.pubKeys[pubUID] = rec
}

func (s *fakeStore) handler() kmipserver.RequestHandler {
	exec := kmipserver.NewBatchExecutor()

	exec.Route(ovh.OperationCreateKeyPair, kmipserver.HandleFunc(func(_ context.Context, req *payloads.CreateKeyPairRequestPayload) (*payloads.CreateKeyPairResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		priv, err := generateKeyFromRequest(req)
		if err != nil {
			return nil, err
		}
		pkix, err := x509.MarshalPKIXPublicKey(priv.Public())
		if err != nil {
			return nil, fmt.Errorf("marshal public key: %w", err)
		}
		rec := &keyRecord{
			privUID: s.nextUID("priv"),
			pubUID:  s.nextUID("pub"),
			privKey: priv,
			pubPKIX: pkix,
		}
		// Capture Name attributes applied at creation via the Template-Attribute.
		// The Common template applies to both the private and public key.
		if req.CommonTemplateAttribute != nil {
			for _, attr := range req.CommonTemplateAttribute.Attribute {
				if attr.AttributeName == ovh.AttributeNameName {
					if n, ok := attr.AttributeValue.(ovh.Name); ok {
						rec.nameAttrs = append(rec.nameAttrs, n.NameValue)
						rec.pubNameAttrs = append(rec.pubNameAttrs, n.NameValue)
					}
				}
			}
		}
		s.keys[rec.privUID] = rec
		s.pubKeys[rec.pubUID] = rec
		return &payloads.CreateKeyPairResponsePayload{
			PrivateKeyUniqueIdentifier: rec.privUID,
			PublicKeyUniqueIdentifier:  rec.pubUID,
		}, nil
	}))

	// Activate — no-op in the fake; keys are always ready to sign.
	exec.Route(ovh.OperationActivate, kmipserver.HandleFunc(func(_ context.Context, req *payloads.ActivateRequestPayload) (*payloads.ActivateResponsePayload, error) {
		return &payloads.ActivateResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
	}))

	// Revoke — records the revocation so tests can assert the plugin deactivates
	// a key before destroying it.
	exec.Route(ovh.OperationRevoke, kmipserver.HandleFunc(func(_ context.Context, req *payloads.RevokeRequestPayload) (*payloads.RevokeResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.revoked[req.UniqueIdentifier] = true
		return &payloads.RevokeResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
	}))

	exec.Route(ovh.OperationAddAttribute, kmipserver.HandleFunc(func(_ context.Context, req *payloads.AddAttributeRequestPayload) (*payloads.AddAttributeResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if req.Attribute.AttributeName == ovh.AttributeNameName {
			if n, ok := req.Attribute.AttributeValue.(ovh.Name); ok {
				if rec, ok := s.keys[req.UniqueIdentifier]; ok {
					rec.nameAttrs = append(rec.nameAttrs, n.NameValue)
				}
				if rec, ok := s.pubKeys[req.UniqueIdentifier]; ok {
					rec.pubNameAttrs = append(rec.pubNameAttrs, n.NameValue)
				}
			}
		}
		// Echo the attribute back as required by the KMIP spec.
		return &payloads.AddAttributeResponsePayload{
			UniqueIdentifier: req.UniqueIdentifier,
			Attribute:        req.Attribute,
		}, nil
	}))

	exec.Route(ovh.OperationModifyAttribute, kmipserver.HandleFunc(func(_ context.Context, req *payloads.ModifyAttributeRequestPayload) (*payloads.ModifyAttributeResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if req.Attribute.AttributeName == ovh.AttributeNameName {
			if n, ok := req.Attribute.AttributeValue.(ovh.Name); ok {
				idx := 0
				if req.Attribute.AttributeIndex != nil {
					idx = int(*req.Attribute.AttributeIndex)
				}
				if rec, ok := s.keys[req.UniqueIdentifier]; ok {
					if idx < len(rec.nameAttrs) {
						rec.nameAttrs[idx] = n.NameValue
					}
				}
				if rec, ok := s.pubKeys[req.UniqueIdentifier]; ok {
					if idx < len(rec.pubNameAttrs) {
						rec.pubNameAttrs[idx] = n.NameValue
					}
				}
			}
		}
		return &payloads.ModifyAttributeResponsePayload{
			UniqueIdentifier: req.UniqueIdentifier,
			Attribute:        req.Attribute,
		}, nil
	}))

	exec.Route(ovh.OperationDeleteAttribute, kmipserver.HandleFunc(func(_ context.Context, req *payloads.DeleteAttributeRequestPayload) (*payloads.DeleteAttributeResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		resp := &payloads.DeleteAttributeResponsePayload{UniqueIdentifier: req.UniqueIdentifier}
		if req.AttributeName == ovh.AttributeNameName && req.AttributeIndex != nil {
			idx := int(*req.AttributeIndex)
			if rec, ok := s.keys[req.UniqueIdentifier]; ok && idx < len(rec.nameAttrs) {
				// The KMIP spec requires echoing back the deleted attribute value.
				resp.Attribute = ovh.Attribute{
					AttributeName:  ovh.AttributeNameName,
					AttributeValue: ovh.Name{NameValue: rec.nameAttrs[idx], NameType: ovh.NameTypeUninterpretedTextString},
				}
				rec.nameAttrs = append(rec.nameAttrs[:idx], rec.nameAttrs[idx+1:]...)
			}
			if rec, ok := s.pubKeys[req.UniqueIdentifier]; ok && idx < len(rec.pubNameAttrs) {
				rec.pubNameAttrs = append(rec.pubNameAttrs[:idx], rec.pubNameAttrs[idx+1:]...)
			}
		}
		return resp, nil
	}))

	exec.Route(ovh.OperationGet, kmipserver.HandleFunc(func(_ context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		rec, ok := s.pubKeys[req.UniqueIdentifier]
		if !ok {
			return nil, fmt.Errorf("object %s not found", req.UniqueIdentifier)
		}
		pkix := make([]byte, len(rec.pubPKIX))
		copy(pkix, rec.pubPKIX)
		return &payloads.GetResponsePayload{
			ObjectType:       ovh.ObjectTypePublicKey,
			UniqueIdentifier: req.UniqueIdentifier,
			Object: &ovh.PublicKey{
				KeyBlock: ovh.KeyBlock{
					KeyFormatType: ovh.KeyFormatTypeX_509,
					KeyValue:      &ovh.KeyValue{Wrapped: &pkix},
				},
			},
		}, nil
	}))

	exec.Route(ovh.OperationGetAttributes, kmipserver.HandleFunc(func(_ context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var attrs []ovh.Attribute
		if rec, ok := s.keys[req.UniqueIdentifier]; ok {
			for _, want := range req.AttributeName {
				switch want {
				case ovh.AttributeNameName:
					for _, n := range rec.nameAttrs {
						attrs = append(attrs, ovh.Attribute{
							AttributeName:  ovh.AttributeNameName,
							AttributeValue: ovh.Name{NameValue: n, NameType: ovh.NameTypeUninterpretedTextString},
						})
					}
				case ovh.AttributeNameLink:
					attrs = append(attrs, ovh.Attribute{
						AttributeName: ovh.AttributeNameLink,
						AttributeValue: ovh.Link{
							LinkType:               ovh.LinkTypePublicKeyLink,
							LinkedObjectIdentifier: rec.pubUID,
						},
					})
				}
			}
		} else if rec, ok := s.pubKeys[req.UniqueIdentifier]; ok {
			for _, want := range req.AttributeName {
				if want == ovh.AttributeNameName {
					for _, n := range rec.pubNameAttrs {
						attrs = append(attrs, ovh.Attribute{
							AttributeName:  ovh.AttributeNameName,
							AttributeValue: ovh.Name{NameValue: n, NameType: ovh.NameTypeUninterpretedTextString},
						})
					}
				}
			}
		}
		return &payloads.GetAttributesResponsePayload{
			UniqueIdentifier: req.UniqueIdentifier,
			Attribute:        attrs,
		}, nil
	}))

	exec.Route(ovh.OperationLocate, kmipserver.HandleFunc(func(_ context.Context, req *payloads.LocateRequestPayload) (*payloads.LocateResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var filterNames []string
		var filterObjectType ovh.ObjectType
		hasObjectType := false
		for _, a := range req.Attribute {
			switch a.AttributeName {
			case ovh.AttributeNameName:
				if n, ok := a.AttributeValue.(ovh.Name); ok {
					filterNames = append(filterNames, n.NameValue)
				}
			case ovh.AttributeNameObjectType:
				if t, ok := a.AttributeValue.(ovh.ObjectType); ok {
					filterObjectType = t
					hasObjectType = true
				}
			}
		}
		matches := func(nameAttrs []string, objectType ovh.ObjectType) bool {
			if !allNamesPresent(nameAttrs, filterNames) {
				return false
			}
			return !hasObjectType || filterObjectType == objectType
		}
		var all []string
		for uid, rec := range s.keys {
			if matches(rec.nameAttrs, ovh.ObjectTypePrivateKey) {
				all = append(all, uid)
			}
		}
		for uid, rec := range s.pubKeys {
			if matches(rec.pubNameAttrs, ovh.ObjectTypePublicKey) {
				all = append(all, uid)
			}
		}
		// Sort for a deterministic order so offset-based pagination is stable.
		sort.Strings(all)
		// Apply pagination (OffsetItems + MaximumItems), mirroring a KMIP server
		// that caps the number of items returned per response.
		start := min(int(req.OffsetItems), len(all))
		end := len(all)
		if req.MaximumItems > 0 && start+int(req.MaximumItems) < end {
			end = start + int(req.MaximumItems)
		}
		return &payloads.LocateResponsePayload{UniqueIdentifier: all[start:end]}, nil
	}))

	exec.Route(ovh.OperationDestroy, kmipserver.HandleFunc(func(_ context.Context, req *payloads.DestroyRequestPayload) (*payloads.DestroyResponsePayload, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		// Destroy removes only the specified object (no implicit cascade), matching
		// the KMIP spec where a client must destroy linked objects explicitly.
		if _, ok := s.keys[req.UniqueIdentifier]; ok {
			delete(s.keys, req.UniqueIdentifier)
		} else {
			delete(s.pubKeys, req.UniqueIdentifier)
		}
		return &payloads.DestroyResponsePayload{UniqueIdentifier: req.UniqueIdentifier}, nil
	}))

	exec.Route(ovh.OperationSign, kmipserver.HandleFunc(func(_ context.Context, req *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error) {
		s.mu.Lock()
		s.lastSignRequest = cloneSignRequest(req)
		rec, ok := s.keys[req.UniqueIdentifier]
		s.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("key %s not found", req.UniqueIdentifier)
		}
		// Use DigestedData (pre-hashed) if set, otherwise Data.
		data := req.DigestedData
		if data == nil {
			data = req.Data
		}
		sig, err := rec.privKey.Sign(rand.Reader, data, signerOptsFromRequest(req))
		if err != nil {
			return nil, fmt.Errorf("sign: %w", err)
		}
		return &payloads.SignResponsePayload{
			UniqueIdentifier: req.UniqueIdentifier,
			SignatureData:    sig,
		}, nil
	}))

	return exec
}

func cloneSignRequest(req *payloads.SignRequestPayload) *payloads.SignRequestPayload {
	if req == nil {
		return nil
	}
	reqCopy := *req
	if req.CryptographicParameters != nil {
		paramsCopy := *req.CryptographicParameters
		reqCopy.CryptographicParameters = &paramsCopy
	}
	return &reqCopy
}

func signerOptsFromRequest(req *payloads.SignRequestPayload) crypto.SignerOpts {
	hash := cryptoHashFromKMIP(req.CryptographicParameters)
	if req.CryptographicParameters != nil && req.CryptographicParameters.DigitalSignatureAlgorithm == ovh.DigitalSignatureAlgorithmRSASSA_PSS {
		opts := &rsa.PSSOptions{Hash: hash}
		if req.CryptographicParameters.SaltLength != nil {
			opts.SaltLength = int(*req.CryptographicParameters.SaltLength)
		}
		return opts
	}
	return hash
}

func cryptoHashFromKMIP(params *ovh.CryptographicParameters) crypto.Hash {
	if params == nil {
		return crypto.SHA256
	}
	switch params.HashingAlgorithm {
	case ovh.HashingAlgorithmSHA_256:
		return crypto.SHA256
	case ovh.HashingAlgorithmSHA_384:
		return crypto.SHA384
	case ovh.HashingAlgorithmSHA_512:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func generateKeyFromRequest(req *payloads.CreateKeyPairRequestPayload) (crypto.Signer, error) {
	if req.CommonTemplateAttribute == nil {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	var algo ovh.CryptographicAlgorithm
	var length int32
	var curve ovh.RecommendedCurve
	for _, a := range req.CommonTemplateAttribute.Attribute {
		switch a.AttributeName {
		case ovh.AttributeNameCryptographicAlgorithm:
			if v, ok := a.AttributeValue.(ovh.CryptographicAlgorithm); ok {
				algo = v
			}
		case ovh.AttributeNameCryptographicLength:
			if v, ok := a.AttributeValue.(int32); ok {
				length = v
			}
		case ovh.AttributeNameCryptographicDomainParameters:
			if v, ok := a.AttributeValue.(ovh.CryptographicDomainParameters); ok {
				curve = v.RecommendedCurve
			}
		}
	}
	switch algo {
	case ovh.CryptographicAlgorithmRSA:
		bits := int(length)
		if bits == 0 {
			bits = 2048
		}
		return rsa.GenerateKey(rand.Reader, bits)
	default:
		c := elliptic.P256()
		if curve == ovh.RecommendedCurveP_384 {
			c = elliptic.P384()
		}
		return ecdsa.GenerateKey(c, rand.Reader)
	}
}

func allNamesPresent(have, required []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, n := range have {
		set[n] = struct{}{}
	}
	for _, r := range required {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}
