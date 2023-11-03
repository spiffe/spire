package azurekeyvault

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/andres-erbsen/clock"
	"github.com/gofrs/uuid/v5"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagertest "github.com/spiffe/spire/pkg/server/plugin/keymanager/test"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	validServerID       = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	validServerIDFile   = "test-server-id"
	validKeyVaultURI    = "https://spire-server.vault.azure.net/"
	validTenantID       = "fake-tenant-id"
	validSubscriptionID = "fake-subscription-id"
	validAppID          = "fake-app-id"
	validAppSecret      = "fake-app-secret"
	trustDomain         = "test.example.org"
	keyName             = "fake-key-name"
	spireKeyID          = "spireKeyID"
	testTimeout         = 60 * time.Second
)

var (
	ctx           = context.Background()
	unixEpoch     = time.Unix(0, 0)
	refreshedDate = unixEpoch.Add(6 * time.Hour)
)

type pluginTest struct {
	plugin    *Plugin
	kmsClient *kmsClientFake
	logHook   *test.Hook
	clockHook *clock.Mock
}

func TestKeyManagerContract(t *testing.T) {
	create := func(t *testing.T) keymanager.KeyManager {
		c := clock.NewMock()
		kmsClient := newKMSClientFake(t, validKeyVaultURI, trustDomain, validServerID, c)
		p := newPlugin(
			func(azcore.TokenCredential, string) (cloudKeyManagementService, error) { return kmsClient, nil },
		)
		km := new(keymanager.V1)
		keyMetadataFile := createKeyMetadataFile(t)

		plugintest.Load(t, builtin(p), km, plugintest.Configuref(`
			key_metadata_file = %q
			key_vault_uri = "https://spire-server.vault.azure.net/"
			use_msi=true
		`, keyMetadataFile))
		return km
	}

	unsupportedSignatureAlgorithms := map[keymanager.KeyType][]x509.SignatureAlgorithm{
		keymanager.ECP256: {x509.ECDSAWithSHA384, x509.ECDSAWithSHA512},
		keymanager.ECP384: {x509.ECDSAWithSHA256, x509.ECDSAWithSHA512},
	}

	keymanagertest.Test(t, keymanagertest.Config{
		Create:                         create,
		UnsupportedSignatureAlgorithms: unsupportedSignatureAlgorithms,
	})
}

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name             string
		err              string
		code             codes.Code
		configureRequest *configv1.ConfigureRequest
		fakeEntries      []fakeKeyEntry
		listKeysErr      string
		getKeyErr        string
		getPublicKeyErr  string
	}{
		{
			name:             "pass with keys",
			configureRequest: configureRequestWithDefaults(t),
			fakeEntries: []fakeKeyEntry{
				makeFakeKeyEntry(t, "key-1", trustDomain, validServerID, azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(2048)),
				makeFakeKeyEntry(t, "key-2", trustDomain, validServerID, azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(4096)),
				makeFakeKeyEntry(t, "key-3", trustDomain, validServerID, azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP256), nil),
				makeFakeKeyEntry(t, "key-4", trustDomain, validServerID, azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP384), nil),
			},
		},
		{
			name:             "pass without keys",
			configureRequest: configureRequestWithDefaults(t),
		},
		{
			name:             "missing key metadata file",
			configureRequest: configureRequestWithVars("", validKeyVaultURI, "", "", "", validAppSecret, "true"),
			err:              "configuration is missing server ID file path",
			code:             codes.InvalidArgument,
		},
		{
			name:             "missing client authentication config",
			configureRequest: configureRequestWithVars(createKeyMetadataFile(t), validKeyVaultURI, "", "", "", "", "false"),
		},
		{
			name:             "use MSI while app secret is set",
			configureRequest: configureRequestWithVars(createKeyMetadataFile(t), validKeyVaultURI, "", "", "", validAppSecret, "true"),
			err:              "invalid configuration, cannot use both MSI and app authentication",
			code:             codes.InvalidArgument,
		},
		{
			name:             "missing Key Vault URI",
			configureRequest: configureRequestWithVars(createKeyMetadataFile(t), "", validTenantID, validSubscriptionID, validAppID, validAppSecret, "false"),
			err:              "configuration is missing the Key Vault URI",
			code:             codes.InvalidArgument,
		},
		{
			name:             "missing tenant ID",
			configureRequest: configureRequestWithVars(createKeyMetadataFile(t), validKeyVaultURI, "", validSubscriptionID, validAppID, validAppSecret, "false"),
			err:              "invalid configuration, missing tenant id",
			code:             codes.InvalidArgument,
		},
		{
			name:             "missing subscription ID ",
			configureRequest: configureRequestWithVars(createKeyMetadataFile(t), validKeyVaultURI, validTenantID, "", validAppID, validAppSecret, "false"),
			err:              "invalid configuration, missing subscription id",
			code:             codes.InvalidArgument,
		},
		{
			name:             "missing server id file path",
			configureRequest: configureRequestWithVars("", validKeyVaultURI, validTenantID, validSubscriptionID, validAppID, validAppSecret, "false"),
			err:              "configuration is missing server ID file path",
			code:             codes.InvalidArgument,
		},
		{
			name:             "missing application ID",
			configureRequest: configureRequestWithVars(createKeyMetadataFile(t), validKeyVaultURI, validTenantID, validSubscriptionID, "", validAppSecret, "false"),
			err:              "invalid configuration, missing application id",
			code:             codes.InvalidArgument,
		},
		{
			name:             "missing application secret",
			configureRequest: configureRequestWithVars(createKeyMetadataFile(t), validKeyVaultURI, validTenantID, validSubscriptionID, validAppID, "", "false"),
			err:              "invalid configuration, missing app secret",
			code:             codes.InvalidArgument,
		},

		{
			name:             "decode error",
			configureRequest: configureRequestWithString("{ malformed json }"),
			err:              "unable to decode configuration: 1:11: illegal char",
			code:             codes.InvalidArgument,
		},
		{
			name:             "list keys error",
			err:              "failed while listing keys: fake list keys error",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(t),
			listKeysErr:      "fake list keys error",
		},
		{
			name:             "get key error",
			err:              "failed to fetch key details: get key error",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(t),
			fakeEntries: []fakeKeyEntry{
				makeFakeKeyEntry(t, "key-1", trustDomain, validServerID, azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(2048)),
			},
			getKeyErr: "get key error",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.kmsClient.setEntries(tt.fakeEntries)
			ts.kmsClient.setListKeysErr(tt.listKeysErr)
			ts.kmsClient.setGetKeyErr(tt.getKeyErr)
			ts.kmsClient.setGetPublicKeyErr(tt.getPublicKeyErr)

			// exercise
			_, err := ts.plugin.Configure(ctx, tt.configureRequest)

			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestGenerateKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	for _, tt := range []struct {
		name            string
		err             string
		code            codes.Code
		logs            []spiretest.LogEntry
		waitForDelete   bool
		fakeEntries     []fakeKeyEntry
		request         *keymanagerv1.GenerateKeyRequest
		createKeyErr    string
		getPublicKeyErr string
		deleteKeyErr    error
		updateKeyErr    string
		tenantID        string
		subscriptionID  string
		appID           string
		appSecret       string
		configureReq    *configv1.ConfigureRequest
	}{
		{
			name: "success: non existing key",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
		{
			name: "success: non existing key with special characters",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   "bundle-acme-foo.bar+rsa",
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
		{
			name: "success: EC 384",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P384,
			},
		},
		{
			name: "success: RSA 2048",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
		},
		{
			name: "success: RSA 4096",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_RSA_4096,
			},
		},
		{
			name: "missing key id",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   "",
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			err:  "key id is required",
			code: codes.InvalidArgument,
		},
		{
			name: "missing key type",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE,
			},
			err:  "key type is required",
			code: codes.InvalidArgument,
		},
		{
			name:         "create key error",
			err:          "failed to create key: something went wrong",
			code:         codes.Internal,
			createKeyErr: "something went wrong",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.kmsClient.setEntries(tt.fakeEntries)
			ts.kmsClient.setCreateKeyErr(tt.createKeyErr)
			ts.kmsClient.setDeleteKeyErr(tt.deleteKeyErr)
			deleteSignal := make(chan error)
			ts.plugin.hooks.scheduleDeleteSignal = deleteSignal

			configureReq := tt.configureReq
			if configureReq == nil {
				configureReq = configureRequestWithDefaults(t)
			}
			_, err := ts.plugin.Configure(ctx, configureReq)
			require.NoError(t, err)

			ts.kmsClient.setGetPublicKeyErr(tt.getPublicKeyErr)

			// exercise
			resp, err := ts.plugin.GenerateKey(ctx, tt.request)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			_, err = ts.plugin.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{
				KeyId: tt.request.KeyId,
			})
			require.NoError(t, err)

			if !tt.waitForDelete {
				spiretest.AssertLogsContainEntries(t, ts.logHook.AllEntries(), tt.logs)
				return
			}

			select {
			case <-deleteSignal:
				// The logs emitted by the deletion goroutine and those that
				// enqueue deletion can be intermixed, so we cannot depend
				// on the exact order of the logs, so we just assert that
				// the expected log lines are present somewhere.
				spiretest.AssertLogsContainEntries(t, ts.logHook.AllEntries(), tt.logs)
			case <-ctx.Done():
				t.Fail()
			}
		})
	}
}

func TestSignData(t *testing.T) {
	sum256 := sha256.Sum256(nil)
	sum384 := sha512.Sum384(nil)
	sum512 := sha512.Sum512(nil)

	for _, tt := range []struct {
		name               string
		request            *keymanagerv1.SignDataRequest
		generateKeyRequest *keymanagerv1.GenerateKeyRequest
		err                string
		code               codes.Code
		signDataError      string
	}{
		{
			name: "pass EC SHA256",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
		{
			name: "pass EC SHA384",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum384[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA384,
				},
			},
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P384,
			},
		},
		{
			name: "pass RSA 2048 SHA 256",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA 2048 SHA 384",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum384[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA384,
				},
			},
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA 2048 SHA 512",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum512[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA512,
				},
			},
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA PSS 2048 SHA 256",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_PssOptions{
					PssOptions: &keymanagerv1.SignDataRequest_PSSOptions{
						HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
						SaltLength:    256,
					},
				},
			},
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA PSS 2048 SHA 384",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum384[:],
				SignerOpts: &keymanagerv1.SignDataRequest_PssOptions{
					PssOptions: &keymanagerv1.SignDataRequest_PSSOptions{
						HashAlgorithm: keymanagerv1.HashAlgorithm_SHA384,
						SaltLength:    384,
					},
				},
			},
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA PSS 2048 SHA 512",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum512[:],
				SignerOpts: &keymanagerv1.SignDataRequest_PssOptions{
					PssOptions: &keymanagerv1.SignDataRequest_PSSOptions{
						HashAlgorithm: keymanagerv1.HashAlgorithm_SHA512,
						SaltLength:    512,
					},
				},
			},
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA 4096 SHA 256",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_RSA_4096,
			},
		},
		{
			name: "pass RSA PSS 4096 SHA 256",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_PssOptions{
					PssOptions: &keymanagerv1.SignDataRequest_PSSOptions{
						HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
						SaltLength:    256,
					},
				},
			},
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_RSA_4096,
			},
		},
		{
			name: "missing key id",
			request: &keymanagerv1.SignDataRequest{
				KeyId: "",
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			err:  "key id is required",
			code: codes.InvalidArgument,
		},
		{
			name: "missing key signer opts",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum256[:],
			},
			err:  "signer opts is required",
			code: codes.InvalidArgument,
		},
		{
			name: "missing hash algorithm",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM,
				},
			},
			err:  "hash algorithm is required",
			code: codes.InvalidArgument,
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
		{
			name: "unsupported combination",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum512[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA512,
				},
			},
			err:  "unsupported combination of key type: EC_P256 and hashing algorithm: SHA512",
			code: codes.InvalidArgument,
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
		{
			name: "non existing key",
			request: &keymanagerv1.SignDataRequest{
				KeyId: "does_not_exists",
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			err:  "key \"does_not_exists\" not found",
			code: codes.NotFound,
		},
		{
			name: "pss options nil",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_PssOptions{
					PssOptions: nil,
				},
			},
			err:  "PSS options are required",
			code: codes.InvalidArgument,
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_RSA_2048,
			},
		},
		{
			name:          "sign error",
			err:           "failed to sign: sign error",
			code:          codes.Internal,
			signDataError: "sign error",
			request: &keymanagerv1.SignDataRequest{
				KeyId: spireKeyID,
				Data:  sum256[:],
				SignerOpts: &keymanagerv1.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanagerv1.HashAlgorithm_SHA256,
				},
			},
			generateKeyRequest: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.kmsClient.setSignDataErr(tt.signDataError)
			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults(t))
			require.NoError(t, err)
			if tt.generateKeyRequest != nil {
				_, err := ts.plugin.GenerateKey(ctx, tt.generateKeyRequest)
				require.NoError(t, err)
			}

			// exercise
			resp, err := ts.plugin.SignData(ctx, tt.request)
			spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
			if tt.code != codes.OK {
				return
			}
			require.NotNil(t, resp)
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	for _, tt := range []struct {
		name           string
		err            string
		code           codes.Code
		generatedKeyID string
		queriedKeyID   string
	}{
		{
			name:           "existing key",
			generatedKeyID: spireKeyID,
			queriedKeyID:   spireKeyID,
		},
		{
			name:           "existing key with special characters",
			generatedKeyID: "bundle-acme-foo.bar+rsa",
			queriedKeyID:   "bundle-acme-foo.bar+rsa",
		},
		{
			name:           "non existing key",
			err:            "key \"some-other-id\" not found",
			code:           codes.NotFound,
			generatedKeyID: "some-id",
			queriedKeyID:   "some-other-id",
		},
		{
			name:           "missing key id",
			err:            "key id is required",
			code:           codes.InvalidArgument,
			generatedKeyID: "some-id",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)

			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults(t))
			require.NoError(t, err)

			_, err = ts.plugin.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{
				KeyId:   tt.generatedKeyID,
				KeyType: keymanagerv1.KeyType_RSA_4096,
			})
			require.NoError(t, err)

			// exercise
			resp, err := ts.plugin.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{
				KeyId: tt.queriedKeyID,
			})
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				return
			}
			require.NotNil(t, resp)
			require.NoError(t, err)
		})
	}
}

func TestGetPublicKeys(t *testing.T) {
	for _, tt := range []struct {
		name            string
		err             string
		generatedKeyIds []string
	}{
		{
			name:            "existing key",
			generatedKeyIds: []string{"key-1", "key-2", "key-3"},
		},
		{
			name: "non existing keys",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)

			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults(t))
			require.NoError(t, err)

			// Generate the keys
			for _, keyID := range tt.generatedKeyIds {
				_, err = ts.plugin.GenerateKey(ctx, &keymanagerv1.GenerateKeyRequest{
					KeyId:   keyID,
					KeyType: keymanagerv1.KeyType_RSA_4096,
				})
				require.NoError(t, err)
			}

			// exercise
			resp, err := ts.plugin.GetPublicKeys(ctx, &keymanagerv1.GetPublicKeysRequest{})

			if tt.err != "" {
				require.Error(t, err)
				require.Equal(t, err.Error(), tt.err)
				return
			}

			require.NotNil(t, resp)
			require.NoError(t, err)
			require.Equal(t, len(tt.generatedKeyIds), len(resp.PublicKeys))
		})
	}
}

func TestRefreshKeys(t *testing.T) {
	entry1 := makeFakeKeyEntry(t, keyNamePrefix+"-"+getUUID(t)+"-spireKey1", trustDomain, validServerID, azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(4096))
	entry2 := makeFakeKeyEntry(t, keyNamePrefix+"-"+getUUID(t)+"-spireKey2", trustDomain, "another-server-id", azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(4096))
	entry3 := makeFakeKeyEntry(t, keyNamePrefix+"-"+getUUID(t)+"-spireKey3", "another-td", validServerID, azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(4096))
	entry4 := makeFakeKeyEntry(t, keyNamePrefix+"-"+getUUID(t)+"-spireKey4", "another-td", "another-server-id", azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(4096))

	for _, tt := range []struct {
		name             string
		configureRequest *configv1.ConfigureRequest
		err              string
		fakeEntries      []fakeKeyEntry
		updateKeyErr     string
	}{
		{
			name:             "refresh keys error",
			configureRequest: configureRequestWithDefaults(t),
			err:              "update failure",
			updateKeyErr:     "update failure",
			fakeEntries: []fakeKeyEntry{
				makeFakeKeyEntry(t, keyName, trustDomain, validServerID, azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(4096)),
			},
		},
		{
			name:             "refresh keys succeeds",
			configureRequest: configureRequestWithDefaults(t),
			fakeEntries: []fakeKeyEntry{
				entry1,
				entry2,
				entry3,
				entry4,
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.kmsClient.setEntries(tt.fakeEntries)
			ts.kmsClient.setUpdateKeyErr(tt.updateKeyErr)
			refreshKeysSignal := make(chan error)
			ts.plugin.hooks.refreshKeysSignal = refreshKeysSignal

			// exercise
			_, err := ts.plugin.Configure(ctx, tt.configureRequest)
			require.NoError(t, err)

			// wait for refresh keys task to be initialized
			err = waitForSignal(t, refreshKeysSignal)
			require.NoError(t, err)
			// move the clock forward so the task is run
			ts.clockHook.Add(6 * time.Hour)
			// wait for refresh keys to be run
			err = waitForSignal(t, refreshKeysSignal)

			// assert
			if tt.updateKeyErr != "" {
				require.NotNil(t, err)
				require.Equal(t, tt.err, err.Error())
				return
			}

			require.NoError(t, err)
			keyEntries := ts.kmsClient.store.fakeKeys
			require.Len(t, keyEntries, len(tt.fakeEntries))

			for _, keyEntry := range keyEntries {
				tags := keyEntry.KeyBundle.Tags
				// Assert that keys belonging to the server are refreshed
				if *tags[tagNameServerTrustDomain] == trustDomain && *tags[tagNameServerID] == validServerID {
					require.EqualValues(t, keyEntry.KeyBundle.Attributes.Updated, &refreshedDate, keyEntry.KeyBundle.Key.KID.Name())
				} else {
					// Assert that keys not belonging to the server are not refreshed
					require.EqualValues(t, keyEntry.KeyBundle.Attributes.Updated, &unixEpoch, keyEntry.KeyBundle.Key.KID.Name())
				}
			}
		})
	}
}

func TestDisposeKeys(t *testing.T) {
	entry1 := makeFakeKeyEntry(t, keyName+"-1", trustDomain, "", azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(4096))
	entry2 := makeFakeKeyEntry(t, keyName+"-2", trustDomain, validServerID, azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(2048))
	entry3 := makeFakeKeyEntry(t, keyName+"-3", trustDomain, "another_server_id", azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP384), nil)
	entry4 := makeFakeKeyEntry(t, keyName+"-4", "another-trust-domain", validServerID, azkeys.JSONWebKeyTypeRSA, nil, to.Ptr(4096))
	entry5 := makeFakeKeyEntry(t, keyName+"-5", "another-trust-domain", "another_server_id", azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP256), nil)
	entry6 := makeFakeKeyEntry(t, keyName+"-6", trustDomain, "another_server_id", azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP384), nil)
	entry7 := makeFakeKeyEntry(t, keyName+"-7", trustDomain, "another_server_id", azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP256), nil)
	entry8 := makeFakeKeyEntry(t, keyName+"-8", trustDomain, "another_server_id", azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP384), nil)
	entry9 := makeFakeKeyEntry(t, keyName+"-9", "some-other-trust-domain", "another_server_id", azkeys.JSONWebKeyTypeEC, to.Ptr(azkeys.JSONWebKeyCurveNameP384), nil)
	for _, tt := range []struct {
		name             string
		configureRequest *configv1.ConfigureRequest
		err              string
		fakeEntries      []fakeKeyEntry
		expectedEntries  []fakeKeyEntry
		listKeysErr      string
		describeKeyErr   string
	}{
		{
			name:             "dispose keys succeeds",
			configureRequest: configureRequestWithDefaults(t),
			fakeEntries: []fakeKeyEntry{
				entry1,
				entry2,
				entry3,
				entry4,
				entry5,
				entry6,
				entry7,
				entry8,
				entry9,
			},
			expectedEntries: []fakeKeyEntry{
				{
					KeyBundle: entry2.KeyBundle,
				},
				{
					KeyBundle: entry4.KeyBundle,
				},
				{
					KeyBundle: entry5.KeyBundle,
				},
				{
					KeyBundle: entry9.KeyBundle,
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.kmsClient.setEntries(tt.fakeEntries)
			ts.kmsClient.setListKeysErr(tt.listKeysErr)
			ts.kmsClient.setGetKeyErr(tt.describeKeyErr)
			ts.kmsClient.setListKeysErr(tt.listKeysErr)
			scheduleDeleteSignal := make(chan error)
			disposeKeysSignal := make(chan error)

			ts.plugin.hooks.disposeKeysSignal = disposeKeysSignal
			ts.plugin.hooks.scheduleDeleteSignal = scheduleDeleteSignal

			// exercise
			_, err := ts.plugin.Configure(ctx, tt.configureRequest)
			require.NoError(t, err)

			// Wait for dispose disposeCryptoKeysTask to be initialized.
			err = waitForSignal(t, disposeKeysSignal)
			require.NoError(t, err)

			// Move the clock to start the task
			ts.clockHook.Add(maxStaleDuration)
			ts.clockHook.Add(1 * time.Second)
			err = waitForSignal(t, disposeKeysSignal)
			require.NoError(t, err)
			// Wait till all the keys we expect to be deleted are deleted
			// Wait for the 1st key to be deleted
			err = waitForSignal(t, scheduleDeleteSignal)
			require.NoError(t, err)
			// Wait for the 2nd key to be deleted
			err = waitForSignal(t, scheduleDeleteSignal)
			require.NoError(t, err)
			// Wait for the 3rd key to be deleted
			err = waitForSignal(t, scheduleDeleteSignal)
			require.NoError(t, err)
			// Wait for the 4th key to be deleted
			err = waitForSignal(t, scheduleDeleteSignal)
			require.NoError(t, err)
			// Wait for the 5th key to be deleted
			err = waitForSignal(t, scheduleDeleteSignal)
			require.NoError(t, err)

			// assert
			storedKeys := ts.kmsClient.store.fakeKeys
			require.Len(t, storedKeys, len(tt.expectedEntries))
			for _, expected := range tt.expectedEntries {
				_, ok := storedKeys[expected.KeyBundle.Key.KID.Name()]
				require.True(t, ok, "Expected key was not present on end result: %q", expected.KeyBundle.Key.KID.Name())
			}
		})
	}
}

func setupTest(t *testing.T) *pluginTest {
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := clock.NewMock()
	kmsClient := newKMSClientFake(t, validKeyVaultURI, trustDomain, validServerID, c)
	p := newPlugin(
		func(azcore.TokenCredential, string) (cloudKeyManagementService, error) { return kmsClient, nil },
	)
	km := new(keymanager.V1)
	plugintest.Load(t, builtin(p), km, plugintest.Log(log))

	p.hooks.clk = c

	return &pluginTest{
		plugin:    p,
		kmsClient: kmsClient,
		logHook:   logHook,
		clockHook: c,
	}
}

func configureRequestWithDefaults(t *testing.T) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration:  serializedConfiguration(createKeyMetadataFile(t), validKeyVaultURI, validTenantID, validSubscriptionID, validAppID, validAppSecret, ""),
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: trustDomain},
	}
}

func getUUID(t *testing.T) string {
	uuid, err := uuid.NewV4()
	require.NoError(t, err)
	return uuid.String()
}

func serializedConfiguration(keyMetadataFile, keyVaultURI, tenantID, subscriptionID, appID, appSecret, useMsi string) string {
	return fmt.Sprintf(`{
		"key_metadata_file":"%s",
		"key_vault_uri":"%s",
		"tenant_id":"%s",
		"subscription_id":"%s",
		"app_id":"%s",
		"app_secret":"%s",
		"use_msi":%s
		}`,
		keyMetadataFile,
		keyVaultURI,
		tenantID,
		subscriptionID,
		appID,
		appSecret,
		useMsi)
}

func configureRequestWithVars(keyMetadataFile, keyVaultURI, tenantID, subscriptionID, appID, appSecret, useMsi string) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration:  serializedConfiguration(keyMetadataFile, keyVaultURI, tenantID, subscriptionID, appID, appSecret, useMsi),
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: trustDomain},
	}
}

func configureRequestWithString(config string) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration: config,
	}
}

func createKeyMetadataFile(t *testing.T) string {
	tempDir := t.TempDir()
	tempFilePath := filepath.ToSlash(filepath.Join(tempDir, validServerIDFile))
	err := os.WriteFile(tempFilePath, []byte(validServerID), 0o600)
	if err != nil {
		t.Error(err)
	}

	return tempFilePath
}

func makeFakeKeyEntry(t *testing.T, keyName, trustDomain, serverID string, keyType azkeys.JSONWebKeyType, curveName *azkeys.JSONWebKeyCurveName, rsaKeySize *int) fakeKeyEntry {
	var publicKey *azkeys.JSONWebKey
	var privateKey crypto.Signer
	keyOperations := getKeyOperations()
	kmsKeyID := validKeyVaultURI + path.Join("keys", fmt.Sprintf("%s-%s-%s", keyNamePrefix, fmt.Sprintf("%s-%s", getUUID(t), keyName), spireKeyID))
	switch {
	case keyType == azkeys.JSONWebKeyTypeEC && *curveName == azkeys.JSONWebKeyCurveNameP256:
		privateKey = testkey.NewEC256(t)
		publicKey = toECKey(privateKey.Public(), kmsKeyID, *curveName, keyOperations)
	case keyType == azkeys.JSONWebKeyTypeEC && *curveName == azkeys.JSONWebKeyCurveNameP384:
		privateKey = testkey.NewEC384(t)
		publicKey = toECKey(privateKey.Public(), kmsKeyID, *curveName, keyOperations)
	case keyType == azkeys.JSONWebKeyTypeRSA && *rsaKeySize == 2048:
		privateKey = testkey.NewRSA2048(t)
		publicKey = toRSAKey(privateKey.Public(), kmsKeyID, keyOperations)
	case keyType == azkeys.JSONWebKeyTypeRSA && *rsaKeySize == 4096:
		privateKey = testkey.NewRSA4096(t)
		publicKey = toRSAKey(privateKey.Public(), kmsKeyID, keyOperations)
	default:
		return fakeKeyEntry{}
	}

	keyAttr := &azkeys.KeyAttributes{
		Enabled: to.Ptr(true),
		Created: &unixEpoch,
		Updated: &unixEpoch,
	}

	tags := make(map[string]*string)
	tags[tagNameServerTrustDomain] = to.Ptr(trustDomain)
	tags[tagNameServerID] = to.Ptr(serverID)
	keyBundle := &azkeys.KeyBundle{
		Attributes: keyAttr,
		Key:        publicKey,
		Tags:       tags,
	}

	keyEntry := fakeKeyEntry{
		KeyBundle:  *keyBundle,
		PrivateKey: privateKey,
	}

	return keyEntry
}

func waitForSignal(t *testing.T, ch chan error) error {
	select {
	case err := <-ch:
		return err
	case <-time.After(testTimeout):
		t.Fail()
	}
	return nil
}
