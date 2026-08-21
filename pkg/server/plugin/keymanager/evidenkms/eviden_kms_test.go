package evidenkms

import (
	"context"
	"fmt"
	"testing"

	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	kmip "github.com/Cosmian/kmip-go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const testServerID = "test-server-id-0001"

// ─── Configure ───────────────────────────────────────────────────────────────

func TestConfigure(t *testing.T) {
	f := kmip.NewFakeKMS()
	defer f.Close()

	for _, tt := range []struct {
		name       string
		config     string
		expectCode codes.Code
		expectMsg  string
	}{
		{
			name: "valid token auth",
			config: fmt.Sprintf(`
				kms_addr            = %q
				server_id           = %q
				insecure_skip_verify = true
				token_auth { token = "test-token" }
			`, f.URL(), testServerID),
			expectCode: codes.OK,
		},
		{
			name: "missing kms_addr",
			config: fmt.Sprintf(`server_id = %q
				token_auth { token = "x" }
			`, testServerID),
			expectCode: codes.InvalidArgument,
			expectMsg:  "kms_addr",
		},
		{
			name: "missing server_id",
			config: fmt.Sprintf(`kms_addr = %q
				token_auth { token = "x" }
			`, f.URL()),
			expectCode: codes.InvalidArgument,
			expectMsg:  "server_id",
		},
		{
			name: "both auth methods set",
			config: fmt.Sprintf(`
				kms_addr  = %q
				server_id = %q
				token_auth { token = "a" }
				cert_auth  { client_cert_path = "x" client_key_path = "y" }
			`, f.URL(), testServerID),
			expectCode: codes.InvalidArgument,
			expectMsg:  "cert_auth and token_auth are mutually exclusive",
		},
		{
			name: "no auth method",
			config: fmt.Sprintf(`kms_addr = %q
				server_id = %q
			`, f.URL(), testServerID),
			expectCode: codes.InvalidArgument,
			expectMsg:  "one of cert_auth",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := New()
			var configErr error
			plugintest.Load(t, builtinKM(p), nil,
				plugintest.CaptureConfigureError(&configErr),
				plugintest.Configure(tt.config),
				plugintest.CoreConfig(catalog.CoreConfig{
					TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
				}),
			)
			spiretest.RequireGRPCStatusHasPrefix(t, configErr, tt.expectCode, tt.expectMsg)
		})
	}
}

// ─── GenerateKey ─────────────────────────────────────────────────────────────

func TestGenerateKey(t *testing.T) {
	for _, tt := range []struct {
		name    string
		keyType keymanagerv1.KeyType
	}{
		{"EC_P256", keymanagerv1.KeyType_EC_P256},
		{"EC_P384", keymanagerv1.KeyType_EC_P384},
		{"RSA_2048", keymanagerv1.KeyType_RSA_2048},
		{"RSA_4096", keymanagerv1.KeyType_RSA_4096},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := kmip.NewFakeKMS()
			defer f.Close()
			_, v1 := loadPluginAndFacade(t, f)

			resp, err := v1.KeyManagerClient.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
				KeyId:   "x509-CA-A",
				KeyType: tt.keyType,
			})
			require.NoError(t, err)
			require.NotNil(t, resp.PublicKey)
			require.Equal(t, "x509-CA-A", resp.PublicKey.Id)
			require.Equal(t, tt.keyType, resp.PublicKey.Type)
			require.NotEmpty(t, resp.PublicKey.PkixData)
		})
	}
}

func TestGenerateKeyMissingID(t *testing.T) {
	f := kmip.NewFakeKMS()
	defer f.Close()
	_, v1 := loadPluginAndFacade(t, f)

	_, err := v1.KeyManagerClient.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   "",
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "key id is required")
}

// ─── SignData ─────────────────────────────────────────────────────────────────

func TestSignData(t *testing.T) {
	f := kmip.NewFakeKMS()
	defer f.Close()
	_, v1 := loadPluginAndFacade(t, f)

	_, err := v1.KeyManagerClient.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   "x509-CA-A",
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	require.NoError(t, err)

	digest := make([]byte, 32)
	resp, err := v1.KeyManagerClient.SignData(context.Background(), &keymanagerv1.SignDataRequest{
		KeyId: "x509-CA-A",
		Data:  digest,
		SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Signature)
}

func TestSignDataKeyNotFound(t *testing.T) {
	f := kmip.NewFakeKMS()
	defer f.Close()
	_, v1 := loadPluginAndFacade(t, f)

	_, err := v1.KeyManagerClient.SignData(context.Background(), &keymanagerv1.SignDataRequest{
		KeyId: "nonexistent",
		Data:  []byte("data"),
		SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
		},
	})
	spiretest.RequireGRPCStatus(t, err, codes.NotFound, `key "nonexistent" not found`)
}

// ─── GetPublicKey / GetPublicKeys ─────────────────────────────────────────────

func TestGetPublicKey(t *testing.T) {
	f := kmip.NewFakeKMS()
	defer f.Close()
	_, v1 := loadPluginAndFacade(t, f)

	_, err := v1.KeyManagerClient.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   "x509-CA-A",
		KeyType: keymanagerv1.KeyType_EC_P256,
	})
	require.NoError(t, err)

	resp, err := v1.KeyManagerClient.GetPublicKey(context.Background(), &keymanagerv1.GetPublicKeyRequest{KeyId: "x509-CA-A"})
	require.NoError(t, err)
	require.Equal(t, "x509-CA-A", resp.PublicKey.Id)
}

func TestGetPublicKeys(t *testing.T) {
	f := kmip.NewFakeKMS()
	defer f.Close()
	_, v1 := loadPluginAndFacade(t, f)

	for _, id := range []string{"x509-CA-A", "jwt-signer-0"} {
		_, err := v1.KeyManagerClient.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
			KeyId:   id,
			KeyType: keymanagerv1.KeyType_EC_P256,
		})
		require.NoError(t, err)
	}

	resp, err := v1.KeyManagerClient.GetPublicKeys(context.Background(), &keymanagerv1.GetPublicKeysRequest{})
	require.NoError(t, err)
	require.Len(t, resp.PublicKeys, 2)
}

// ─── Key recovery on reconfigure ─────────────────────────────────────────────

func TestKeyRecoveryOnConfigure(t *testing.T) {
	f := kmip.NewFakeKMS()
	defer f.Close()

	// First instance creates a key with known SPIRE key ID and type.
	_, v1a := loadPluginAndFacade(t, f)
	_, err := v1a.KeyManagerClient.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
		KeyId:   "x509-CA-A",
		KeyType: keymanagerv1.KeyType_EC_P384,
	})
	require.NoError(t, err)

	// Second instance on same fake KMS should recover the key with the correct ID + type.
	_, v1b := loadPluginAndFacade(t, f)

	// GetPublicKey by SPIRE key ID — must work after restart, not just by UID.
	getResp, err := v1b.KeyManagerClient.GetPublicKey(context.Background(),
		&keymanagerv1.GetPublicKeyRequest{KeyId: "x509-CA-A"})
	require.NoError(t, err, "GetPublicKey by SPIRE key ID must work after restart")
	require.Equal(t, "x509-CA-A", getResp.PublicKey.Id, "recovered key must have original SPIRE key ID")
	require.Equal(t, keymanagerv1.KeyType_EC_P384, getResp.PublicKey.Type, "recovered key must have original key type")
	require.NotEmpty(t, getResp.PublicKey.PkixData)
}

func TestKeyRecoveryMultipleKeys(t *testing.T) {
	f := kmip.NewFakeKMS()
	defer f.Close()

	_, v1a := loadPluginAndFacade(t, f)
	for _, tc := range []struct {
		id  string
		kt  keymanagerv1.KeyType
	}{
		{"x509-CA-A", keymanagerv1.KeyType_EC_P256},
		{"jwt-signer-0", keymanagerv1.KeyType_EC_P384},
	} {
		_, err := v1a.KeyManagerClient.GenerateKey(context.Background(), &keymanagerv1.GenerateKeyRequest{
			KeyId:   tc.id,
			KeyType: tc.kt,
		})
		require.NoError(t, err)
	}

	// Restart.
	_, v1b := loadPluginAndFacade(t, f)
	resp, err := v1b.KeyManagerClient.GetPublicKeys(context.Background(), &keymanagerv1.GetPublicKeysRequest{})
	require.NoError(t, err)
	require.Len(t, resp.PublicKeys, 2)

	// Verify both keys are addressable by SPIRE key ID.
	for _, id := range []string{"x509-CA-A", "jwt-signer-0"} {
		_, err := v1b.KeyManagerClient.GetPublicKey(context.Background(),
			&keymanagerv1.GetPublicKeyRequest{KeyId: id})
		require.NoError(t, err, "key %q must be recoverable by SPIRE key ID", id)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func loadPluginAndFacade(t *testing.T, f *kmip.FakeKMS) (*Plugin, *keymanager.V1) {
	t.Helper()
	p := New()
	v1 := new(keymanager.V1)
	plugintest.Load(t, builtinKM(p), v1,
		plugintest.Configure(fmt.Sprintf(`
			kms_addr            = %q
			server_id           = %q
			insecure_skip_verify = true
			token_auth { token = "test-token" }
		`, f.URL(), testServerID)),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		}),
	)
	return p, v1
}

func builtinKM(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
