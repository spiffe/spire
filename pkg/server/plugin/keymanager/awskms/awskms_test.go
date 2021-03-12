package awskms

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/catalog"
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
	validKeyPrefix       = "SPIRE_SERVER_KEY/"
	keyID                = "abcd-fghi"
	KeyArn               = "arn:aws:kms:region:1234:key/abcd-fghi"
	aliasName            = "alias/SPIRE_SERVER_KEY/spireKeyID"
	spireKeyID           = "spireKeyID"
)

var (
	ctx = context.Background()
)

type pluginTest struct {
	plugin     *Plugin
	fakeClient *kmsClientFake
	logHook    *test.Hook
}

func setupTest(t *testing.T) *pluginTest {
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	fakeClient := newKMSClientFake(t)
	kmsPlugin := newPlugin(func(ctx context.Context, c *Config) (kmsClient, error) {
		return fakeClient, nil
	})
	kmsCatalog := catalog.MakePlugin(pluginName, keymanager.PluginServer(kmsPlugin))
	var km keymanager.KeyManager
	spiretest.LoadPlugin(t, kmsCatalog, &km, spiretest.Logger(log))

	return &pluginTest{
		plugin:     kmsPlugin,
		fakeClient: fakeClient,
		logHook:    logHook,
	}
}

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
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
				{
					AliasName: aws.String(aliasName + "01"),
					KeyID:     aws.String(keyID + "01"),
					KeySpec:   types.CustomerMasterKeySpecRsa2048,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
				{
					AliasName: aws.String(aliasName + "02"),
					KeyID:     aws.String(keyID + "02"),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
				{
					AliasName: aws.String(aliasName + "03"),
					KeyID:     aws.String(keyID + "03"),
					KeySpec:   types.CustomerMasterKeySpecEccNistP256,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
				{
					AliasName: aws.String(aliasName + "04"),
					KeyID:     aws.String(keyID + "04"),
					KeySpec:   types.CustomerMasterKeySpecEccNistP384,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
				{
					AliasName: aws.String("alias/wrong_prefix"),
					KeyID:     aws.String("foo_id"),
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
				 		"region":"region",
						"key_prefix":"prefix"
					 }`),
		},
		{
			name: "missing secret access key",
			configureRequest: configureRequestWith(`{
				 		"access_key_id":"access_key",
				 		"region":"region",
						"key_prefix":"prefix"
					 }`),
		},
		{
			name: "missing region",
			configureRequest: configureRequestWith(`{
				 		"access_key_id":"access_key",
				 		"secret_access_key":"secret_access_key",
						"key_prefix":"prefix"
				 	}`),
			err:  "aws_kms: configuration is missing a region",
			code: codes.InvalidArgument,
		},
		{
			name: "missing key prefix",
			configureRequest: configureRequestWith(`{
				 		"access_key_id":"access_key",
				 		"secret_access_key":"secret_access_key",
						"region":"region",
				 	}`),
			err:  "aws_kms: configuration is missing key prefix",
			code: codes.InvalidArgument,
		},
		{
			name:             "decode error",
			configureRequest: configureRequestWith("{ malformed json }"),
			err:              "aws_kms: unable to decode configuration: 1:11: illegal char",
			code:             codes.InvalidArgument,
		},
		{
			name:             "list aliases error",
			err:              "aws_kms: failed to fetch aliases: fake list aliases error",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(),
			listAliasesErr:   "fake list aliases error",
		},
		{
			name:             "describe key error",
			err:              "aws_kms: failed to describe key: describe key error",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
					KeySpec:   types.CustomerMasterKeySpecRsa2048,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
			describeKeyErr: "describe key error",
		},
		{
			name:             "unsupported key error",
			err:              "aws_kms: unsupported key spec: unsupported key spec",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
					KeySpec:   "unsupported key spec",
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name:             "get public key error",
			err:              "aws_kms: failed to fetch aliases: aws_kms: failed to get public key: get public key error",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
			getPublicKeyErr: "get public key error",
		},
		{
			name:             "alias without a key",
			err:              "aws_kms: failed to fetch aliases: found SPIRE alias without key: \"arn:aws:kms:region:1234:alias/SPIRE_SERVER_KEY/no_key\"",
			code:             codes.FailedPrecondition,
			configureRequest: configureRequestWithDefaults(),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
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
			err:              "aws_kms: failed to fetch aliases: aws_kms: found disabled SPIRE key: \"arn:aws:kms:region:1234:key/abcd-fghi\", alias: \"arn:aws:kms:region:1234:alias/SPIRE_SERVER_KEY/spireKeyID\"",
			code:             codes.FailedPrecondition,
			configureRequest: configureRequestWithDefaults(),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
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
			ts := setupTest(t)
			ts.fakeClient.setEntries(tt.fakeEntries)
			ts.fakeClient.setListAliasesErr(tt.listAliasesErr)
			ts.fakeClient.setDescribeKeyErr(tt.describeKeyErr)
			ts.fakeClient.setgetPublicKeyErr(tt.getPublicKeyErr)

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
	for _, tt := range []struct {
		name                   string
		err                    string
		code                   codes.Code
		logs                   []spiretest.LogEntry
		waitForDelete          bool
		fakeEntries            []fakeKeyEntry
		request                *keymanager.GenerateKeyRequest
		createKeyErr           string
		getPublicKeyErr        string
		scheduleKeyDeletionErr error
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
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
					KeySpec:   types.CustomerMasterKeySpecEccNistP256,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
			waitForDelete: true,
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Key deleted",
					Data: logrus.Fields{
						keyArnTag:        KeyArn,
						"subsystem_name": "built-in_plugin.aws_kms",
					},
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
			err:  "aws_kms: unsupported key type: RSA_1024",
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
			err:  "aws_kms: key id is required",
			code: codes.InvalidArgument,
		},
		{
			name: "missing key type",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_UNSPECIFIED_KEY_TYPE,
			},
			err:  "aws_kms: key type is required",
			code: codes.InvalidArgument,
		},
		{
			name:         "create key error",
			err:          "aws_kms: failed to create key: something went wrong",
			code:         codes.Internal,
			createKeyErr: "something went wrong",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
		},
		{
			name:           "create alias error",
			err:            "aws_kms: failed to create alias: something went wrong",
			code:           codes.Internal,
			createAliasErr: "something went wrong",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
		},
		{
			name:           "update alias error",
			err:            "aws_kms: failed to update alias: something went wrong",
			code:           codes.Internal,
			updateAliasErr: "something went wrong",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
					KeySpec:   types.CustomerMasterKeySpecEccNistP256,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name:            "get public key error",
			err:             "aws_kms: failed to get public key: public key error",
			code:            codes.Internal,
			getPublicKeyErr: "public key error",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
		},
		{
			name: "schedule delete not found error",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
			scheduleKeyDeletionErr: &types.NotFoundException{Message: aws.String("not found")},
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
					KeySpec:   types.CustomerMasterKeySpecEccNistP256,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
			waitForDelete: true,
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "No such key, dropping from delete schedule",
					Data: logrus.Fields{
						keyArnTag:        KeyArn,
						"subsystem_name": "built-in_plugin.aws_kms",
					},
				},
			},
		},
		{
			name: "invalid arn error",
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
			scheduleKeyDeletionErr: &types.InvalidArnException{Message: aws.String("invalid arn")},
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
					KeySpec:   types.CustomerMasterKeySpecEccNistP256,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
			waitForDelete: true,
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Invalid ARN, dropping from delete schedule",
					Data: logrus.Fields{
						keyArnTag:        KeyArn,
						"subsystem_name": "built-in_plugin.aws_kms",
					},
				},
			},
		},
		{
			name:                   "schedule key deletion error",
			scheduleKeyDeletionErr: errors.New("schedule key deletion error"),
			request: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_EC_P256,
			},
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
					KeySpec:   types.CustomerMasterKeySpecEccNistP256,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
			waitForDelete: true,
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "It was not possible to schedule key for deletion",
					Data: logrus.Fields{
						keyArnTag:        KeyArn,
						"reason":         "schedule key deletion error",
						"subsystem_name": "built-in_plugin.aws_kms",
					},
				},
				{
					Level:   logrus.DebugLevel,
					Message: "Key re-enqueued for deletion",
					Data: logrus.Fields{
						keyArnTag:        KeyArn,
						"subsystem_name": "built-in_plugin.aws_kms",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.fakeClient.setEntries(tt.fakeEntries)
			ts.fakeClient.setCreateKeyErr(tt.createKeyErr)
			ts.fakeClient.setCreateAliasesErr(tt.createAliasErr)
			ts.fakeClient.setUpdateAliasesErr(tt.updateAliasErr)
			ts.fakeClient.setScheduleKeyDeletionErr(tt.scheduleKeyDeletionErr)
			ts.plugin.hooks.deleteSignal = make(chan struct{}, 2)

			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults())
			require.NoError(t, err)

			ts.fakeClient.setgetPublicKeyErr(tt.getPublicKeyErr)

			// exercise
			resp, err := ts.plugin.GenerateKey(ctx, tt.request)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			if tt.waitForDelete {
				<-ts.plugin.hooks.deleteSignal
				spiretest.AssertLastLogs(t, ts.logHook.AllEntries(), tt.logs)
			}
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
			err:  "aws_kms: key id is required",
			code: codes.InvalidArgument,
		},
		{
			name: "missing key signer opts",
			request: &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
			},
			err:  "aws_kms: signer opts is required",
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
			err:  "aws_kms: hash algorithm is required",
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
			err:  "aws_kms: unsupported combination of keytype: EC_P256 and hashing algorithm: SHA512",
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
			err:  "aws_kms: no such key \"does_not_exists\"",
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
			err:  "aws_kms: PSS options are required",
			code: codes.InvalidArgument,
			generateKeyRequest: &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanager.KeyType_RSA_2048,
			},
		},
		{
			name:          "sign error",
			err:           "aws_kms: failed to sign: sign error",
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
			ts := setupTest(t)
			ts.fakeClient.setSignDataErr(tt.signDataError)
			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults())
			require.NoError(t, err)
			if tt.generateKeyRequest != nil {
				_, err := ts.plugin.GenerateKey(ctx, tt.generateKeyRequest)
				require.NoError(t, err)
			}

			// exercise
			resp, err := ts.plugin.SignData(ctx, tt.request)
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
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name:  "non existing key",
			err:   "aws_kms: no such key \"spireKeyID\"",
			code:  codes.NotFound,
			keyID: spireKeyID,
		},
		{
			name: "missing key id",
			err:  "aws_kms: key id is required",
			code: codes.InvalidArgument,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.fakeClient.setEntries(tt.fakeEntries)

			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults())
			require.NoError(t, err)

			// exercise
			resp, err := ts.plugin.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
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
					AliasName: aws.String(aliasName),
					KeyID:     aws.String(keyID),
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
			ts := setupTest(t)
			ts.fakeClient.setEntries(tt.fakeEntries)
			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults())
			require.NoError(t, err)

			// exercise
			resp, err := ts.plugin.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})

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
					AliasName:   aws.String(aliasName),
					TargetKeyId: aws.String(keyID),
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			//setup
			ts := setupTest(t)

			//exercise
			resp, err := ts.plugin.GetPluginInfo(ctx, &plugin.GetPluginInfoRequest{})

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
		Configuration: serializedConfiguration(validAccessKeyID, validSecretAccessKey, validRegion, validKeyPrefix),
	}
}

func serializedConfiguration(accessKeyID, secretAccessKey, region string, keyPrefix string) string {
	return fmt.Sprintf(`{
		"access_key_id": "%s",
		"secret_access_key": "%s",
		"region":"%s",
		"key_prefix":"%s"
		}`,
		accessKeyID,
		secretAccessKey,
		region,
		keyPrefix)
}
