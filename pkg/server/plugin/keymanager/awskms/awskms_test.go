package awskms

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	// Defaults used for testing
	validAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	validSecretAccessKey = "secret"
	validRegion          = "us-west-2"
	kmsKeyID             = "abcd-fghi"
	kmsAlias             = "alias/SPIRE_SERVER_KEY/spireKeyID"
	spireKeyID           = "spireKeyID"
)

var (
	ctx = context.Background()
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name             string
		err              string
		code             codes.Code
		configureRequest *plugin.ConfigureRequest
		fakeEntries      []fakeKeyEntry
		listAliasesErr   string
		describeKeyErr   string
		getPublicKeyErr  string
	}{

		{
			name:             "pass with keys",
			configureRequest: configureRequestWithDefaults(),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String("alias/SPIRE_SERVER_KEY_B/spireKeyID"),
					KeyID:     aws.String("foo"),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
				{
					AliasName: aws.String(kmsAlias + "01"),
					KeyID:     aws.String(kmsKeyID + "01"),
					KeySpec:   types.CustomerMasterKeySpecRsa2048,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
				{
					AliasName: aws.String(kmsAlias + "02"),
					KeyID:     aws.String(kmsKeyID + "02"),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
				{
					AliasName: aws.String(kmsAlias + "03"),
					KeyID:     aws.String(kmsKeyID + "03"),
					KeySpec:   types.CustomerMasterKeySpecEccNistP256,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
				{
					AliasName: aws.String(kmsAlias + "04"),
					KeyID:     aws.String(kmsKeyID + "04"),
					KeySpec:   types.CustomerMasterKeySpecEccNistP384,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name:             "pass without keys",
			configureRequest: configureRequestWithDefaults(),
		},
		{
			name: "missing access key id",
			configureRequest: configureRequestWith(`{
				 		"secret_access_key":"secret_access_key",
				 		"region":"region"
					 }`),
		},
		{
			name: "missing secret access key",
			configureRequest: configureRequestWith(`{
				 		"access_key_id":"access_key",
				 		"region":"region"
					 }`),
		},
		{
			name: "missing region",
			configureRequest: configureRequestWith(`{
				 		"access_key_id":"access_key",
				 		"secret_access_key":"secret_access_key",
				 	}`),
			err:  "awskms: configuration is missing a region",
			code: codes.InvalidArgument,
		},
		{
			name:             "decode error",
			configureRequest: configureRequestWith("{ malformed json }"),
			err:              "awskms: unable to decode configuration: 1:11: illegal char",
			code:             codes.InvalidArgument,
		},
		{
			name:             "list aliases error",
			err:              "failed to fetch keys: fake list aliases error",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(),
			listAliasesErr:   "fake list aliases error",
		},
		{
			name:             "describe key error",
			err:              "awskms: failed to describe key: describe key error",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(kmsAlias),
					KeyID:     aws.String(kmsKeyID),
					KeySpec:   types.CustomerMasterKeySpecRsa2048,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
			describeKeyErr: "describe key error",
		},
		{
			name:             "unsupported key error",
			err:              "awskms: unsupported key spec: unsupported key spec",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(kmsAlias),
					KeyID:     aws.String(kmsKeyID),
					KeySpec:   "unsupported key spec",
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name:             "get public key error",
			err:              "awskms: failed to build cache of KMS keys: awskms: failed to get public key: get public key error",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(kmsAlias),
					KeyID:     aws.String(kmsKeyID),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
			getPublicKeyErr: "get public key error",
		},
		{
			name:             "alias without a key",
			err:              "awskms: failed to build cache of KMS keys: found SPIRE alias without key: \"alias/SPIRE_SERVER_KEY/no_key\"",
			code:             codes.FailedPrecondition,
			configureRequest: configureRequestWithDefaults(),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(kmsAlias),
					KeyID:     aws.String(kmsKeyID),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
				{
					AliasName: aws.String("alias/SPIRE_SERVER_KEY/no_key"),
					KeyID:     nil,
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name:             "disabled key",
			err:              "awskms: failed to build cache of KMS keys: awskms: found disabled SPIRE key: \"abcd-fghi\", alias: \"alias/SPIRE_SERVER_KEY/spireKeyID\"",
			code:             codes.FailedPrecondition,
			configureRequest: configureRequestWithDefaults(),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(kmsAlias),
					KeyID:     aws.String(kmsKeyID),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   false,
					PublicKey: []byte("foo"),
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			fakeClient := newKMSClientFake(t)
			fakeClient.setEntries(tt.fakeEntries)
			fakeClient.setListAliasesErr(tt.listAliasesErr)
			fakeClient.setDescribeKeyErr(tt.describeKeyErr)
			fakeClient.setgetPublicKeyErr(tt.getPublicKeyErr)

			p := newPlugin(func(ctx context.Context, c *Config) (kmsClient, error) {
				return fakeClient, nil
			})
			p.SetLogger(hclog.NewNullLogger())

			// exercise
			_, err := p.Configure(ctx, tt.configureRequest)

			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestGenerateKey(t *testing.T) {
	for _, tt := range []struct {
		name                   string
		err                    string
		code                   codes.Code
		fakeEntries            []fakeKeyEntry
		request                *keymanager.GenerateKeyRequest
		createKeyErr           string
		getPublicKeyErr        string
		scheduleKeyDeletionErr string
		createAliasErr         string
		updateAliasErr         string
	}{
		{
			name: "success: non existing key",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
		},
		{
			name: "success: replace old key",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(kmsAlias),
					KeyID:     aws.String(kmsKeyID),
					KeySpec:   types.CustomerMasterKeySpecEccNistP256,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name: "success: EC 384",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P384,
			},
		},
		{
			name: "failure unsupported key spec",
			err:  "awskms: unsupported key type: RSA_1024",
			code: codes.Internal,
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_1024,
			},
		},
		{
			name: "success: RSA 2048",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_2048,
			},
		},
		{
			name: "success: RSA 4096",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_4096,
			},
		},
		{
			name: "missing key id",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   "",
				KeyType: keymanager.KeyType_EC_P256,
			},
			err:  "awskms: key id is required",
			code: codes.InvalidArgument,
		},
		{
			name: "missing key type",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_UNSPECIFIED_KEY_TYPE,
			},
			err:  "awskms: key type is required",
			code: codes.InvalidArgument,
		},
		{
			name:         "create key error",
			err:          "awskms: failed to create key: something went wrong",
			code:         codes.Internal,
			createKeyErr: "something went wrong",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
		},
		{
			name:           "create alias error",
			err:            "awskms: failed to create alias: something went wrong",
			code:           codes.Internal,
			createAliasErr: "something went wrong",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
		},
		{
			name:           "update alias error",
			err:            "awskms: failed to update alias: something went wrong",
			code:           codes.Internal,
			updateAliasErr: "something went wrong",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(kmsAlias),
					KeyID:     aws.String(kmsKeyID),
					KeySpec:   types.CustomerMasterKeySpecEccNistP256,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name:            "get public key error",
			err:             "awskms: failed to get public key: public key error",
			code:            codes.Internal,
			getPublicKeyErr: "public key error",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
		},
		{
			name:                   "schedule key deletion error",
			scheduleKeyDeletionErr: "schedule key deletion error",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(kmsAlias),
					KeyID:     aws.String(kmsKeyID),
					KeySpec:   types.CustomerMasterKeySpecEccNistP256,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			fakeClient := newKMSClientFake(t)
			fakeClient.setEntries(tt.fakeEntries)
			fakeClient.setCreateKeyErr(tt.createKeyErr)
			fakeClient.setCreateAliasesErr(tt.createAliasErr)
			fakeClient.setUpdateAliasesErr(tt.updateAliasErr)

			p := newPlugin(func(ctx context.Context, c *Config) (kmsClient, error) {
				return fakeClient, nil
			})
			p.SetLogger(hclog.NewNullLogger())

			_, err := p.Configure(ctx, configureRequestWithDefaults())
			require.NoError(t, err)

			fakeClient.setgetPublicKeyErr(tt.getPublicKeyErr)

			// exercise
			resp, err := p.GenerateKey(ctx, tt.request)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
		})
	}
}

func TestSignData(t *testing.T) {
	for _, tt := range []struct {
		name               string
		request            *keymanager.SignDataRequest
		generateKeyRequest *keymanager.GenerateKeyRequest
		err                string
		code               codes.Code
		signDataError      string
	}{
		{
			name: "pass EC SHA256",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_SHA256,
				},
			},
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
		},
		{
			name: "pass EC SHA384",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_SHA384,
				},
			},
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P384,
			},
		},
		{
			name: "pass RSA 2048 SHA 256",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_SHA256,
				},
			},
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA 2048 SHA 384",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_SHA384,
				},
			},
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA 2048 SHA 512",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_SHA512,
				},
			},
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA PSS 2048 SHA 256",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_PssOptions{
					PssOptions: &keymanager.PSSOptions{
						HashAlgorithm: keymanager.HashAlgorithm_SHA256,
						SaltLength:    256,
					},
				},
			},
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA PSS 2048 SHA 384",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_PssOptions{
					PssOptions: &keymanager.PSSOptions{
						HashAlgorithm: keymanager.HashAlgorithm_SHA384,
						SaltLength:    384,
					},
				},
			},
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA PSS 2048 SHA 512",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_PssOptions{
					PssOptions: &keymanager.PSSOptions{
						HashAlgorithm: keymanager.HashAlgorithm_SHA512,
						SaltLength:    512,
					},
				},
			},
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_2048,
			},
		},
		{
			name: "pass RSA 4096 SHA 256",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_SHA256,
				},
			},
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_4096,
			},
		},
		{
			name: "pass RSA PSS 4096 SHA 256",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_PssOptions{
					PssOptions: &keymanager.PSSOptions{
						HashAlgorithm: keymanager.HashAlgorithm_SHA256,
						SaltLength:    256,
					},
				},
			},
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_4096,
			},
		},
		{
			name: "missing key id",
			request: &keymanager.SignDataRequest{
				KeyId: "",
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_SHA256,
				},
			},
			err:  "awskms: key id is required",
			code: codes.InvalidArgument,
		},
		{
			name: "missing key signer opts",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
			},
			err:  "awskms: signer opts is required",
			code: codes.InvalidArgument,
		},
		{
			name: "missing hash algorithm",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM,
				},
			},
			err:  "awskms: hash algorithm is required",
			code: codes.InvalidArgument,
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
		},
		{
			name: "unsupported combination",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_SHA512,
				},
			},
			err:  "awskms: unsupported combination of keytype: EC_P256 and hashing algorithm: SHA512",
			code: codes.InvalidArgument,
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
		},
		{
			name: "non existing key",
			request: &keymanager.SignDataRequest{
				KeyId: "does_not_exists",
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_SHA256,
				},
			},
			err:  "awskms: no such key \"does_not_exists\"",
			code: codes.NotFound,
		},
		{
			name: "pss options nil",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_PssOptions{
					PssOptions: nil,
				},
			},
			err:  "awskms: PSS options are required",
			code: codes.InvalidArgument,
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_2048,
			},
		},
		{
			name:          "sign error",
			err:           "awskms: failed to sign: sign error",
			code:          codes.Internal,
			signDataError: "sign error",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_SHA256,
				},
			},
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			fakeClient := newKMSClientFake(t)
			fakeClient.setSignDataErr(tt.signDataError)

			p := newPlugin(func(ctx context.Context, c *Config) (kmsClient, error) {
				return fakeClient, nil
			})
			p.SetLogger(hclog.NewNullLogger())
			_, err := p.Configure(ctx, configureRequestWithDefaults())
			require.NoError(t, err)

			if tt.generateKeyRequest != nil {
				_, err := p.GenerateKey(ctx, tt.generateKeyRequest)
				require.NoError(t, err)
			}

			// exercise
			resp, err := p.SignData(ctx, tt.request)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				return
			}

			require.NotNil(t, resp)
			require.NoError(t, err)
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	for _, tt := range []struct {
		name        string
		err         string
		code        codes.Code
		fakeEntries []fakeKeyEntry

		keyID string
	}{
		{
			name:  "existing key",
			keyID: spireKeyID,
			fakeEntries: []fakeKeyEntry{

				{
					AliasName: aws.String(kmsAlias),
					KeyID:     aws.String(kmsKeyID),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name:  "non existing key",
			err:   "awskms: no such key \"spireKeyID\"",
			code:  codes.NotFound,
			keyID: spireKeyID,
		},
		{
			name: "missing key id",
			err:  "awskms: key id is required",
			code: codes.InvalidArgument,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			fakeClient := newKMSClientFake(t)
			fakeClient.setEntries(tt.fakeEntries)

			p := newPlugin(func(ctx context.Context, c *Config) (kmsClient, error) {
				return fakeClient, nil
			})
			p.SetLogger(hclog.NewNullLogger())
			_, err := p.Configure(ctx, configureRequestWithDefaults())
			require.NoError(t, err)

			// exercise
			resp, err := p.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
				KeyId: tt.keyID,
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
		name        string
		err         string
		fakeEntries []fakeKeyEntry
	}{
		{
			name: "existing key",
			fakeEntries: []fakeKeyEntry{

				{
					AliasName: aws.String(kmsAlias),
					KeyID:     aws.String(kmsKeyID),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name: "non existing keys",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			fakeClient := newKMSClientFake(t)
			fakeClient.setEntries(tt.fakeEntries)

			p := newPlugin(func(ctx context.Context, c *Config) (kmsClient, error) {
				return fakeClient, nil
			})
			p.SetLogger(hclog.NewNullLogger())
			_, err := p.Configure(ctx, configureRequestWithDefaults())
			require.NoError(t, err)

			// exercise
			resp, err := p.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})

			if tt.err != "" {
				require.Error(t, err)
				require.Equal(t, err.Error(), tt.err)
				return
			}

			require.NotNil(t, resp)
			require.NoError(t, err)
			require.Equal(t, len(tt.fakeEntries), len(resp.PublicKeys))
		})
	}
}

func TestGetPluginInfo(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  string

		aliases []types.AliasListEntry
	}{
		{
			name: "pass",
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := newKMSClientFake(t)
			p := newPlugin(func(ctx context.Context, c *Config) (kmsClient, error) {
				return fakeClient, nil
			})
			p.SetLogger(hclog.NewNullLogger())

			resp, err := p.GetPluginInfo(ctx, &plugin.GetPluginInfoRequest{})

			require.NotNil(t, resp)
			require.NoError(t, err)
		})
	}
}

func configureRequestWith(config string) *plugin.ConfigureRequest {
	return &plugin.ConfigureRequest{
		Configuration: config,
	}
}

func configureRequestWithDefaults() *plugin.ConfigureRequest {
	return &plugin.ConfigureRequest{
		Configuration: serializedConfiguration(validAccessKeyID, validSecretAccessKey, validRegion),
	}
}

func serializedConfiguration(accessKeyID, secretAccessKey, region string) string {
	return fmt.Sprintf(`{
		"access_key_id": "%s",
		"secret_access_key": "%s",
		"region":"%s"
		}`,
		accessKeyID,
		secretAccessKey,
		region)
}
