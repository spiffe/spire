package awskms

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagertest "github.com/spiffe/spire/pkg/server/plugin/keymanager/test"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	// Defaults used for testing
	validAccessKeyID     = "AKIAIOSFODNN7EXAMPLE" //nolint:gosec // This is a fake access key ID only used as test input
	validSecretAccessKey = "secret"
	validRegion          = "us-west-2"
	validServerIDFile    = "server_id_test"
	validPolicyFile      = "custom_policy_file.json"
	validServerID        = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	keyID                = "abcd-fghi"
	KeyArn               = "arn:aws:kms:region:1234:key/abcd-fghi"
	aliasName            = "alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/spireKeyID"
	spireKeyID           = "spireKeyID"
	testTimeout          = 60 * time.Second
)

var (
	ctx             = context.Background()
	isWindows       = runtime.GOOS == "windows"
	unixEpoch       = time.Unix(0, 0)
	refreshedDate   = unixEpoch.Add(6 * time.Hour)
	customPolicy    = `{custom_policy}`
	roleBasedPolicy = `
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "Allow full access to the SPIRE Server role",
			"Effect": "Allow",
			"Principal": {
				"AWS": "arn:aws:iam::example-account-id:role/example-assumed-role-name"
			},
			"Action": "kms:*",
			"Resource": "*"
		},
		{
			"Sid": "Allow KMS console to display the key and policy",
			"Effect": "Allow",
			"Principal": {
			    "AWS": "arn:aws:iam::example-account-id:root"
			},
			"Action": [
				"kms:Describe*",
				"kms:List*",
				"kms:Get*"
			],
			"Resource": "*"
		}
	]
}`
)

func TestKeyManagerContract(t *testing.T) {
	create := func(t *testing.T) keymanager.KeyManager {
		dir := spiretest.TempDir(t)
		c := clock.NewMock()
		fakeKMSClient := newKMSClientFake(t, c)
		fakeSTSClient := newSTSClientFake()
		p := newPlugin(
			func(aws.Config) (kmsClient, error) { return fakeKMSClient, nil },
			func(aws.Config) (stsClient, error) { return fakeSTSClient, nil },
		)
		km := new(keymanager.V1)
		keyIdentifierFile := filepath.Join(dir, "metadata")
		if isWindows {
			keyIdentifierFile = filepath.ToSlash(keyIdentifierFile)
		}
		plugintest.Load(t, builtin(p), km, plugintest.Configuref(`
			region = "fake-region"
			key_metadata_file = %q
		`, keyIdentifierFile))
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

type pluginTest struct {
	plugin        *Plugin
	fakeKMSClient *kmsClientFake
	fakeSTSClient *stsClientFake
	logHook       *test.Hook
	clockHook     *clock.Mock
}

func setupTest(t *testing.T) *pluginTest {
	log, logHook := test.NewNullLogger()
	log.Level = logrus.DebugLevel

	c := clock.NewMock()
	fakeKMSClient := newKMSClientFake(t, c)
	fakeSTSClient := newSTSClientFake()
	p := newPlugin(
		func(aws.Config) (kmsClient, error) { return fakeKMSClient, nil },
		func(aws.Config) (stsClient, error) { return fakeSTSClient, nil },
	)
	km := new(keymanager.V1)
	plugintest.Load(t, builtin(p), km, plugintest.Log(log))

	p.hooks.clk = c

	return &pluginTest{
		plugin:        p,
		fakeKMSClient: fakeKMSClient,
		fakeSTSClient: fakeSTSClient,
		logHook:       logHook,
		clockHook:     c,
	}
}

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		name             string
		err              string
		code             codes.Code
		configureRequest *configv1.ConfigureRequest
		fakeEntries      []fakeKeyEntry
		listAliasesErr   string
		describeKeyErr   string
		getPublicKeyErr  string
	}{
		{
			name:             "pass with keys",
			configureRequest: configureRequestWithDefaults(t),
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
					AliasName: aws.String("alias/SPIRE_SERVER/wrong_prefix"),
					KeyID:     aws.String("foo_id"),
					KeySpec:   types.CustomerMasterKeySpecEccNistP384,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name:             "pass without keys",
			configureRequest: configureRequestWithDefaults(t),
		},
		{
			name:             "pass with identity file",
			configureRequest: configureRequestWithVars("", "secret_access_key", "region", KeyIdentifierFile, getKeyIdentifierFile(t), ""),
		},
		{
			name:             "pass with identity value",
			configureRequest: configureRequestWithVars("", "secret_access_key", "region", KeyIdentifierValue, "server-id", ""),
		},
		{
			name:             "missing access key id",
			configureRequest: configureRequestWithVars("", "secret_access_key", "region", KeyMetadataFile, getKeyIdentifierFile(t), ""),
		},
		{
			name:             "missing secret access key",
			configureRequest: configureRequestWithVars("access_key", "", "region", KeyMetadataFile, getKeyIdentifierFile(t), ""),
		},
		{
			name:             "missing region",
			configureRequest: configureRequestWithVars("access_key_id", "secret_access_key", "", KeyMetadataFile, getKeyIdentifierFile(t), ""),
			err:              "configuration is missing a region",
			code:             codes.InvalidArgument,
		},
		{
			name:             "missing server id file path",
			configureRequest: configureRequestWithVars("access_key_id", "secret_access_key", "region", KeyMetadataFile, "", ""),
			err:              "configuration requires server id or server id file path",
			code:             codes.InvalidArgument,
		},
		{
			name:             "key identifier file and key identifier value",
			configureRequest: configureRequestWithString(`{"access_key_id":"access_key_id","secret_access_key":"secret_access_key","region":"region","key_identifier_file":"key_identifier_file","key_identifier_value":"key_identifier_value","key_policy_file":""}`),
			err:              "configuration must not contain both server id and server id file path",
			code:             codes.InvalidArgument,
		},
		{
			name:             "key metadata file and key identifier file",
			configureRequest: configureRequestWithString(`{"access_key_id":"access_key_id","secret_access_key":"secret_access_key","region":"region","key_metadata_file":"key_metadata_file","key_identifier_file":"key_identifier_file","key_policy_file":""}`),
			err:              "configuration must not contain both 'key_identifier_file' and deprecated 'key_metadata_file'",
			code:             codes.InvalidArgument,
		},
		{
			name:             "key metadata value invalid character",
			configureRequest: configureRequestWithString(`{"access_key_id":"access_key_id","secret_access_key":"secret_access_key","region":"region","key_identifier_value":"@key_identifier_value@","key_policy_file":""}`),
			err:              "Key identifier must contain only alphanumeric characters, forward slashes (/), underscores (_), and dashes (-)",
			code:             codes.InvalidArgument,
		},
		{
			name:             "key metadata value too long",
			configureRequest: configureRequestWithString(`{"access_key_id":"access_key_id","secret_access_key":"secret_access_key","region":"region","key_identifier_value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","key_policy_file":""}`),
			err:              "Key identifier must not be longer than 256 characters",
			code:             codes.InvalidArgument,
		},
		{
			name:             "key metadata value starts with illegal alias",
			configureRequest: configureRequestWithString(`{"access_key_id":"access_key_id","secret_access_key":"secret_access_key","region":"region","key_identifier_value":"alias/aws/key_identifier_value","key_policy_file":""}`),
			err:              "Key identifier must not start with alias/aws/",
			code:             codes.InvalidArgument,
		},
		{
			name:             "custom policy file does not exists",
			configureRequest: configureRequestWithVars("access_key", "secret_access_key", "region", KeyMetadataFile, getEmptyKeyIdentifierFile(t), "non-existent-file.json"),
			err:              fmt.Sprintf("failed to read file configured in 'key_policy_file': open non-existent-file.json: %s", spiretest.FileNotFound()),
			code:             codes.Internal,
		},
		{
			name:             "use custom policy file",
			configureRequest: configureRequestWithVars("access_key", "secret_access_key", "region", KeyMetadataFile, getEmptyKeyIdentifierFile(t), getCustomPolicyFile(t)),
		},
		{
			name:             "new server id file path",
			configureRequest: configureRequestWithVars("access_key_id", "secret_access_key", "region", KeyMetadataFile, getEmptyKeyIdentifierFile(t), ""),
		},
		{
			name:             "decode error",
			configureRequest: configureRequestWithString("{ malformed json }"),
			err:              "unable to decode configuration: 1:11: illegal char",
			code:             codes.InvalidArgument,
		},
		{
			name:             "list aliases error",
			err:              "failed to fetch aliases: fake list aliases error",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(t),
			listAliasesErr:   "fake list aliases error",
		},
		{
			name:             "describe key error",
			err:              "failed to describe key: describe key error",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(t),
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
			err:              "unsupported key spec: unsupported key spec",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(t),
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
			err:              "failed to fetch aliases: failed to get public key: get public key error",
			code:             codes.Internal,
			configureRequest: configureRequestWithDefaults(t),
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
			name:             "disabled key",
			err:              "failed to fetch aliases: found disabled SPIRE key: \"arn:aws:kms:region:1234:key/abcd-fghi\", alias: \"arn:aws:kms:region:1234:alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/spireKeyID\"",
			code:             codes.FailedPrecondition,
			configureRequest: configureRequestWithDefaults(t),
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
			ts.fakeKMSClient.setEntries(tt.fakeEntries)
			ts.fakeKMSClient.setListAliasesErr(tt.listAliasesErr)
			ts.fakeKMSClient.setDescribeKeyErr(tt.describeKeyErr)
			ts.fakeKMSClient.setgetPublicKeyErr(tt.getPublicKeyErr)

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
		request                *keymanagerv1.GenerateKeyRequest
		createKeyErr           string
		getPublicKeyErr        string
		scheduleKeyDeletionErr error
		createAliasErr         string
		updateAliasErr         string
		getCallerIdentityErr   string
		instanceAccountID      string
		instanceRoleARN        string
		expectedKeyPolicy      *string
		configureReq           *configv1.ConfigureRequest
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
			name: "success: non existing key with default SPIRE policy and assumed role",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			configureReq:      configureRequestWithVars("access_key_id", "secret_access_key", "region", KeyMetadataFile, getEmptyKeyIdentifierFile(t), ""),
			instanceAccountID: "example-account-id",
			instanceRoleARN:   "arn:aws:sts::example-account-id:assumed-role/example-assumed-role-name/example-instance-id",
			expectedKeyPolicy: &roleBasedPolicy,
		},
		{
			name: "success: non existing key with custom policy",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			configureReq:      configureRequestWithVars("access_key_id", "secret_access_key", "region", KeyMetadataFile, getEmptyKeyIdentifierFile(t), getCustomPolicyFile(t)),
			instanceAccountID: "example-account-id",
			instanceRoleARN:   "arn:aws:sts::example-account-id:assumed-role/example-assumed-role-name/example-instance-id",
			expectedKeyPolicy: &customPolicy,
		},
		{
			name: "success: replace old key",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            aws.String(aliasName),
					KeyID:                aws.String(keyID),
					KeySpec:              types.CustomerMasterKeySpecEccNistP256,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					AliasLastUpdatedDate: &unixEpoch,
				},
			},
			waitForDelete: true,
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Key deleted",
					Data: logrus.Fields{
						keyArnTag: KeyArn,
					},
				},
			},
		},
		{
			name: "success: replace old key with special characters",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   "bundle-acme-foo.bar+rsa",
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/bundle-acme-foo_2ebar_2brsa"),
					KeyID:                aws.String(keyID),
					KeySpec:              types.CustomerMasterKeySpecEccNistP256,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					AliasLastUpdatedDate: &unixEpoch,
				},
			},
			waitForDelete: true,
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.DebugLevel,
					Message: "Key deleted",
					Data: logrus.Fields{
						keyArnTag: KeyArn,
					},
				},
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
		{
			name:           "create alias error",
			err:            "failed to create alias: something went wrong",
			code:           codes.Internal,
			createAliasErr: "something went wrong",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
		{
			name:           "update alias error",
			err:            "failed to update alias: something went wrong",
			code:           codes.Internal,
			updateAliasErr: "something went wrong",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
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
			err:             "failed to get public key: public key error",
			code:            codes.Internal,
			getPublicKeyErr: "public key error",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
		},
		{
			name: "schedule delete not found error",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
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
					Message: "Failed to schedule key deletion",
					Data: logrus.Fields{
						reasonTag: "No such key",
						keyArnTag: KeyArn,
					},
				},
			},
		},
		{
			name: "invalid arn error",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
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
					Message: "Failed to schedule key deletion",
					Data: logrus.Fields{
						reasonTag: "Invalid ARN",
						keyArnTag: KeyArn,
					},
				},
			},
		},
		{
			name: "invalid key state error",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			scheduleKeyDeletionErr: &types.KMSInvalidStateException{Message: aws.String("invalid state")},
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
					Message: "Failed to schedule key deletion",
					Data: logrus.Fields{
						reasonTag: "Key was on invalid state for deletion",
						keyArnTag: KeyArn,
					},
				},
			},
		},
		{
			name:                   "schedule key deletion error",
			scheduleKeyDeletionErr: errors.New("schedule key deletion error"),
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
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
						keyArnTag: KeyArn,
						"reason":  "schedule key deletion error",
					},
				},
				{
					Level:   logrus.DebugLevel,
					Message: "Key re-enqueued for deletion",
					Data: logrus.Fields{
						keyArnTag: KeyArn,
					},
				},
			},
		},
		{
			name: "fail to get caller identity",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			configureReq:         configureRequestWithVars("access_key_id", "secret_access_key", "region", KeyMetadataFile, getEmptyKeyIdentifierFile(t), ""),
			getCallerIdentityErr: "something went wrong",
			err:                  "cannot get caller identity: something went wrong",
			code:                 codes.Internal,
		},
		{
			name: "incomplete ARN",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			configureReq:    configureRequestWithVars("access_key_id", "secret_access_key", "region", KeyMetadataFile, getEmptyKeyIdentifierFile(t), ""),
			instanceRoleARN: "arn:aws:sts::example-account-id",
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "In a future version of SPIRE, it will be mandatory for the SPIRE servers to assume an AWS IAM Role when using the default AWS KMS key policy. Please assign an IAM role to this SPIRE Server instance.",
				},
			},
		},
		{
			name: "missing role in ARN",
			request: &keymanagerv1.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keymanagerv1.KeyType_EC_P256,
			},
			configureReq:    configureRequestWithVars("access_key_id", "secret_access_key", "region", KeyMetadataFile, getKeyIdentifierFile(t), ""),
			instanceRoleARN: "arn:aws:sts::example-account-id:user/development",
			logs: []spiretest.LogEntry{
				{
					Level:   logrus.WarnLevel,
					Message: "In a future version of SPIRE, it will be mandatory for the SPIRE servers to assume an AWS IAM Role when using the default AWS KMS key policy. Please assign an IAM role to this SPIRE Server instance.",
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.fakeKMSClient.setEntries(tt.fakeEntries)
			ts.fakeKMSClient.setCreateKeyErr(tt.createKeyErr)
			ts.fakeKMSClient.setCreateAliasesErr(tt.createAliasErr)
			ts.fakeKMSClient.setUpdateAliasErr(tt.updateAliasErr)
			ts.fakeKMSClient.setScheduleKeyDeletionErr(tt.scheduleKeyDeletionErr)
			deleteSignal := make(chan error)
			ts.plugin.hooks.scheduleDeleteSignal = deleteSignal
			ts.fakeKMSClient.setExpectedKeyPolicy(tt.expectedKeyPolicy)
			ts.fakeSTSClient.setGetCallerIdentityErr(tt.getCallerIdentityErr)
			ts.fakeSTSClient.setGetCallerIdentityAccount(tt.instanceAccountID)
			ts.fakeSTSClient.setGetCallerIdentityArn(tt.instanceRoleARN)

			configureReq := tt.configureReq
			if configureReq == nil {
				configureReq = configureRequestWithDefaults(t)
			}
			_, err := ts.plugin.Configure(ctx, configureReq)
			require.NoError(t, err)

			ts.fakeKMSClient.setgetPublicKeyErr(tt.getPublicKeyErr)

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
			case <-time.After(testTimeout):
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
			err:  "unsupported combination of keytype: EC_P256 and hashing algorithm: SHA512",
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
			ts.fakeKMSClient.setSignDataErr(tt.signDataError)
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
			name:  "existing key with special characters",
			keyID: "bundle-acme-foo.bar+rsa",
			fakeEntries: []fakeKeyEntry{
				{
					AliasName: aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/bundle-acme-foo_2ebar_2brsa"),
					KeyID:     aws.String(keyID),
					KeySpec:   types.CustomerMasterKeySpecRsa4096,
					Enabled:   true,
					PublicKey: []byte("foo"),
				},
			},
		},
		{
			name:  "non existing key",
			err:   "key \"spireKeyID\" not found",
			code:  codes.NotFound,
			keyID: spireKeyID,
		},
		{
			name: "missing key id",
			err:  "key id is required",
			code: codes.InvalidArgument,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.fakeKMSClient.setEntries(tt.fakeEntries)

			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults(t))
			require.NoError(t, err)

			// exercise
			resp, err := ts.plugin.GetPublicKey(ctx, &keymanagerv1.GetPublicKeyRequest{
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
			ts.fakeKMSClient.setEntries(tt.fakeEntries)
			_, err := ts.plugin.Configure(ctx, configureRequestWithDefaults(t))
			require.NoError(t, err)

			// exercise
			resp, err := ts.plugin.GetPublicKeys(ctx, &keymanagerv1.GetPublicKeysRequest{})

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

func TestRefreshAliases(t *testing.T) {
	for _, tt := range []struct {
		name             string
		configureRequest *configv1.ConfigureRequest
		err              string
		fakeEntries      []fakeKeyEntry
		expectedEntries  []fakeKeyEntry
		updateAliasErr   string
	}{
		{
			name:             "refresh aliases error",
			configureRequest: configureRequestWithDefaults(t),
			err:              "update failure",
			updateAliasErr:   "update failure",
			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_01"),
					KeyID:                aws.String("key_id_01"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
			},
		},
		{
			name:             "refresh aliases succeeds",
			configureRequest: configureRequestWithDefaults(t),
			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_01"),
					KeyID:                aws.String("key_id_01"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_02"),
					KeyID:                aws.String("key_id_02"),
					KeySpec:              types.CustomerMasterKeySpecRsa2048,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/another_server_id/id_03"),
					KeyID:                aws.String("key_id_03"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP384,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/another_td/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_04"),
					KeyID:                aws.String("key_id_04"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/another_td/another_server_id/id_05"),
					KeyID:                aws.String("key_id_05"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP384,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/unrelated"),
					KeyID:                aws.String("key_id_06"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP384,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/unrelated/unrelated/id_07"),
					KeyID:                aws.String("key_id_07"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP384,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_08"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
			},

			expectedEntries: []fakeKeyEntry{
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_01"),
					KeyID:                aws.String("key_id_01"),
					AliasLastUpdatedDate: &refreshedDate,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_02"),
					KeyID:                aws.String("key_id_02"),
					AliasLastUpdatedDate: &refreshedDate,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/another_server_id/id_03"),
					KeyID:                aws.String("key_id_03"),
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/another_td/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_04"),
					KeyID:                aws.String("key_id_04"),
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/another_td/another_server_id/id_05"),
					KeyID:                aws.String("key_id_05"),
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/unrelated"),
					KeyID:                aws.String("key_id_06"),
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/unrelated/unrelated/id_07"),
					KeyID:                aws.String("key_id_07"),
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_08"),
					AliasLastUpdatedDate: &unixEpoch,
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.fakeKMSClient.setEntries(tt.fakeEntries)
			ts.fakeKMSClient.setUpdateAliasErr(tt.updateAliasErr)
			refreshAliasesSignal := make(chan error)
			ts.plugin.hooks.refreshAliasesSignal = refreshAliasesSignal

			// exercise
			_, err := ts.plugin.Configure(ctx, tt.configureRequest)
			require.NoError(t, err)

			// wait for refresh alias task to be initialized
			_ = waitForSignal(t, refreshAliasesSignal)
			// move the clock forward so the task is run
			ts.clockHook.Add(6 * time.Hour)
			// wait for refresh aliases to be run
			err = waitForSignal(t, refreshAliasesSignal)

			// assert
			if tt.updateAliasErr != "" {
				require.NotNil(t, err)
				require.Equal(t, tt.err, err.Error())
				return
			}

			require.NoError(t, err)
			storedAliases := ts.fakeKMSClient.store.aliases
			require.Len(t, storedAliases, 7)
			storedKeys := ts.fakeKMSClient.store.keyEntries
			require.Len(t, storedKeys, len(tt.expectedEntries))
			for _, expected := range tt.expectedEntries {
				if expected.AliasName == nil {
					continue
				}
				// check aliases
				alias, ok := storedAliases[*expected.AliasName]
				require.True(t, ok, "Expected alias was not present on end result: %q", *expected.AliasName)
				require.EqualValues(t, expected.AliasLastUpdatedDate.String(), alias.KeyEntry.AliasLastUpdatedDate.String(), *expected.AliasName)

				// check keys
				key, ok := storedKeys[*expected.KeyID]
				require.True(t, ok, "Expected alias was not present on end result: %q", *expected.KeyID)
				require.EqualValues(t, expected.AliasLastUpdatedDate.String(), key.AliasLastUpdatedDate.String(), *expected.KeyID)
			}
		})
	}
}

func TestDisposeAliases(t *testing.T) {
	for _, tt := range []struct {
		name             string
		configureRequest *configv1.ConfigureRequest
		err              string
		fakeEntries      []fakeKeyEntry
		expectedEntries  []fakeKeyEntry
		listAliasesErr   string
		describeKeyErr   string
		deleteAliasErr   string
	}{
		{
			name:             "dispose aliases succeeds",
			configureRequest: configureRequestWithDefaults(t),

			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_01"),
					KeyID:                aws.String("key_id_01"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_02"),
					KeyID:                aws.String("key_id_02"),
					KeySpec:              types.CustomerMasterKeySpecRsa2048,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/another_server_id/id_03"),
					KeyID:                aws.String("key_id_03"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP384,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/another_td/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_04"),
					KeyID:                aws.String("key_id_04"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/another_td/another_server/id_05"),
					KeyID:                aws.String("key_id_05"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP256,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/unrelated"),
					KeyID:                aws.String("key_id_06"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP256,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/unrelated/unrelated/id_07"),
					KeyID:                aws.String("key_id_07"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP256,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_08"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP256,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/another_server_id/id_09"),
					KeyID:                aws.String("key_id_09"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP384,
					Enabled:              false,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
			},

			expectedEntries: []fakeKeyEntry{
				{
					AliasName: aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_01"),
					KeyID:     aws.String("key_id_01"),
				},
				{
					AliasName: aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_02"),
					KeyID:     aws.String("key_id_02"),
				},
				{
					AliasName: aws.String("alias/SPIRE_SERVER/another_td/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_04"),
					KeyID:     aws.String("key_id_04"),
				},
				{
					AliasName: aws.String("alias/SPIRE_SERVER/another_td/another_server/id_05"),
					KeyID:     aws.String("key_id_05"),
				},
				{
					AliasName: aws.String("alias/SPIRE_SERVER/unrelated"),
					KeyID:     aws.String("key_id_06"),
				},
				{
					AliasName: aws.String("alias/SPIRE_SERVER/unrelated/unrelated/id_07"),
					KeyID:     aws.String("key_id_07"),
				},
				{
					AliasName: aws.String("alias/SPIRE_SERVER/test_example_org/another_server_id/id_09"),
					KeyID:     aws.String("key_id_09"),
				},
			},
		},
		{
			name:             "list aliases error",
			configureRequest: configureRequestWithDefaults(t),
			err:              "list aliases failure",
			listAliasesErr:   "list aliases failure",
			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_01"),
					KeyID:                aws.String("key_id_01"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
			},
		},
		{
			name:             "describe key error",
			configureRequest: configureRequestWithDefaults(t),
			err:              "describe key failure",
			describeKeyErr:   "describe key failure",
			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/another_server/id_01"),
					KeyID:                aws.String("key_id_01"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
			},
		},
		{
			name:             "delete alias error",
			configureRequest: configureRequestWithDefaults(t),
			err:              "delete alias failure",
			deleteAliasErr:   "delete alias failure",
			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/another_server/id_01"),
					KeyID:                aws.String("key_id_01"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.fakeKMSClient.setEntries(tt.fakeEntries)
			// this is so dispose keys blocks on init and allows to test dispose aliases isolated
			ts.plugin.hooks.disposeKeysSignal = make(chan error)
			disposeAliasesSignal := make(chan error)
			ts.plugin.hooks.disposeAliasesSignal = disposeAliasesSignal
			deleteSignal := make(chan error)
			ts.plugin.hooks.scheduleDeleteSignal = deleteSignal

			// exercise
			_, err := ts.plugin.Configure(ctx, tt.configureRequest)
			require.NoError(t, err)

			ts.fakeKMSClient.setListAliasesErr(tt.listAliasesErr)
			ts.fakeKMSClient.setDescribeKeyErr(tt.describeKeyErr)
			ts.fakeKMSClient.setDeleteAliasErr(tt.deleteAliasErr)

			// wait for dispose aliases task to be initialized
			_ = waitForSignal(t, disposeAliasesSignal)
			// move the clock forward so the task is run
			ts.clockHook.Add(aliasThreshold)
			// wait for dispose aliases to be run
			// first run at 24hs won't dispose keys due to threshold being two weeks
			_ = waitForSignal(t, disposeAliasesSignal)
			// wait for dispose aliases to be run
			err = waitForSignal(t, disposeAliasesSignal)
			// assert errors
			if tt.err != "" {
				require.NotNil(t, err)
				require.Equal(t, tt.err, err.Error())
				return
			}
			// wait for schedule delete to be run
			_ = waitForSignal(t, deleteSignal)
			// assert end result
			require.NoError(t, err)
			storedAliases := ts.fakeKMSClient.store.aliases
			require.Len(t, storedAliases, 7)
			storedKeys := ts.fakeKMSClient.store.keyEntries
			require.Len(t, storedKeys, 8)

			for _, expected := range tt.expectedEntries {
				if expected.AliasName == nil {
					continue
				}
				// check aliases
				_, ok := storedAliases[*expected.AliasName]
				require.True(t, ok, "Expected alias was not present on end result: %q", *expected.AliasName)
				// check keys
				_, ok = storedKeys[*expected.KeyID]
				require.True(t, ok, "Expected alias was not present on end result: %q", *expected.KeyID)
			}
		})
	}
}

func TestDisposeKeys(t *testing.T) {
	for _, tt := range []struct {
		name             string
		configureRequest *configv1.ConfigureRequest
		err              string
		fakeEntries      []fakeKeyEntry
		expectedEntries  []fakeKeyEntry
		listKeysErr      string
		describeKeyErr   string
		listAliasesErr   string
	}{
		{
			name:             "dispose keys succeeds",
			configureRequest: configureRequestWithDefaults(t),

			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_01"),
					Description:          aws.String("SPIRE_SERVER_KEY/test_example_org"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_02"),
					KeyID:                aws.String("key_id_02"),
					Description:          aws.String("SPIRE_SERVER_KEY/test_example_org"),
					KeySpec:              types.CustomerMasterKeySpecRsa2048,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/another_server_id/id_03"),
					KeyID:                aws.String("key_id_03"),
					Description:          aws.String("SPIRE_SERVER_KEY/test_example_org"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP384,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/another_td/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_04"),
					KeyID:                aws.String("key_id_04"),
					Description:          aws.String("SPIRE_SERVER_KEY/another_td"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/another_td/another_server_id/id_05"),
					KeyID:                aws.String("key_id_05"),
					Description:          aws.String("SPIRE_SERVER_KEY/another_td"),
					KeySpec:              types.CustomerMasterKeySpecEccNistP256,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/unrelated"),
					KeyID:                aws.String("key_id_06"),
					Description:          nil,
					KeySpec:              types.CustomerMasterKeySpecEccNistP256,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/unrelated/unrelated/id_07"),
					KeyID:                aws.String("key_id_07"),
					Description:          nil,
					KeySpec:              types.CustomerMasterKeySpecEccNistP384,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_08"),
					Description:          nil,
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            aws.String("alias/SPIRE_SERVER/test_example_org/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/id_01"),
					KeyID:                aws.String("key_id_09"),
					Description:          aws.String("SPIRE_SERVER_KEY/test_example_org"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_10"),
					Description:          aws.String("SPIRE_SERVER_KEY/another_td"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_11"),
					Description:          aws.String("SPIRE_SERVER_KEY/"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_12"),
					Description:          aws.String("SPIRE_SERVER_KEY"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_13"),
					Description:          aws.String("test_example_org"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_14"),
					Description:          aws.String("unrelated"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_15"),
					Description:          aws.String("disabled key"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              false,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_16"),
					Description:          aws.String("SPIRE_SERVER_KEY/test_example_org/extra"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
			},

			expectedEntries: []fakeKeyEntry{
				{
					KeyID: aws.String("key_id_02"),
				},
				{
					KeyID: aws.String("key_id_03"),
				},
				{
					KeyID: aws.String("key_id_04"),
				},
				{
					KeyID: aws.String("key_id_05"),
				},
				{
					KeyID: aws.String("key_id_06"),
				},
				{
					KeyID: aws.String("key_id_07"),
				},
				{
					KeyID: aws.String("key_id_08"),
				},
				{
					KeyID: aws.String("key_id_09"),
				},
				{
					KeyID: aws.String("key_id_10"),
				},
				{
					KeyID: aws.String("key_id_11"),
				},
				{
					KeyID: aws.String("key_id_12"),
				},
				{
					KeyID: aws.String("key_id_13"),
				},
				{
					KeyID: aws.String("key_id_14"),
				},
				{
					KeyID: aws.String("key_id_15"),
				},
				{
					KeyID: aws.String("key_id_16"),
				},
			},
		},
		{
			name:             "list keys error",
			configureRequest: configureRequestWithDefaults(t),
			err:              "list keys failure",
			listKeysErr:      "list keys failure",
			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_01"),
					Description:          aws.String("SPIRE_SERVER_KEY/test_example_org"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
			},
		},
		{
			name:             "list aliases error",
			configureRequest: configureRequestWithDefaults(t),
			err:              "list aliases failure",
			listAliasesErr:   "list aliases failure",
			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_01"),
					Description:          aws.String("SPIRE_SERVER_KEY/test_example_org"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
			},
		},
		{
			name:             "describe key error",
			configureRequest: configureRequestWithDefaults(t),
			err:              "describe key failure",
			describeKeyErr:   "describe key failure",
			fakeEntries: []fakeKeyEntry{
				{
					AliasName:            nil,
					KeyID:                aws.String("key_id_01"),
					Description:          aws.String("SPIRE_SERVER_KEY/test_example_org"),
					KeySpec:              types.CustomerMasterKeySpecRsa4096,
					Enabled:              true,
					PublicKey:            []byte("foo"),
					CreationDate:         &unixEpoch,
					AliasLastUpdatedDate: &unixEpoch,
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// setup
			ts := setupTest(t)
			ts.fakeKMSClient.setEntries(tt.fakeEntries)

			// this is so dispose aliases blocks on init and allows to test dispose keys isolated
			ts.plugin.hooks.disposeAliasesSignal = make(chan error)
			disposeKeysSignal := make(chan error)
			ts.plugin.hooks.disposeKeysSignal = disposeKeysSignal
			deleteSignal := make(chan error)
			ts.plugin.hooks.scheduleDeleteSignal = deleteSignal

			// exercise
			_, err := ts.plugin.Configure(ctx, tt.configureRequest)
			require.NoError(t, err)

			ts.fakeKMSClient.setListKeysErr(tt.listKeysErr)
			ts.fakeKMSClient.setDescribeKeyErr(tt.describeKeyErr)
			ts.fakeKMSClient.setListAliasesErr(tt.listAliasesErr)

			// wait for dispose keys task to be initialized
			_ = waitForSignal(t, disposeKeysSignal)
			// move the clock forward so the task is run
			ts.clockHook.Add(48 * time.Hour)
			// wait for dispose keys to be run
			err = waitForSignal(t, disposeKeysSignal)
			// assert errors
			if tt.err != "" {
				require.NotNil(t, err)
				require.Equal(t, tt.err, err.Error())
				return
			}
			// wait for schedule delete to be run
			_ = waitForSignal(t, deleteSignal)

			// assert
			storedKeys := ts.fakeKMSClient.store.keyEntries
			require.Len(t, storedKeys, len(tt.expectedEntries))
			for _, expected := range tt.expectedEntries {
				_, ok := storedKeys[*expected.KeyID]
				require.True(t, ok, "Expected key was not present on end result: %q", *expected.KeyID)
			}
		})
	}
}

func configureRequestWithString(config string) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration:  config,
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "test.example.org"},
	}
}

type KeyIdentifierConfigName string

const (
	KeyMetadataFile    KeyIdentifierConfigName = "key_metadata_file"
	KeyIdentifierFile  KeyIdentifierConfigName = "key_identifier_file"
	KeyIdentifierValue KeyIdentifierConfigName = "key_identifier_value"
)

func configureRequestWithVars(accessKeyID, secretAccessKey, region, keyIdentifierConfigName KeyIdentifierConfigName, keyIdentifierConfigValue, keyPolicyFile string) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration: fmt.Sprintf(`{
			"access_key_id": "%s",
			"secret_access_key": "%s",
			"region":"%s",
			"%s":"%s",
			"key_policy_file":"%s"
			}`,
			accessKeyID,
			secretAccessKey,
			region,
			keyIdentifierConfigName,
			keyIdentifierConfigValue,
			keyPolicyFile),
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "test.example.org"},
	}
}

func configureRequestWithDefaults(t *testing.T) *configv1.ConfigureRequest {
	return &configv1.ConfigureRequest{
		HclConfiguration:  serializedConfiguration(validAccessKeyID, validSecretAccessKey, validRegion, KeyMetadataFile, getKeyIdentifierFile(t)),
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "test.example.org"},
	}
}

func serializedConfiguration(accessKeyID, secretAccessKey, region string, keyIdentifierConfigName KeyIdentifierConfigName, keyIdentifierConfigValue string) string {
	return fmt.Sprintf(`{
		"access_key_id": "%s",
		"secret_access_key": "%s",
		"region":"%s",
		"%s":"%s"
		}`,
		accessKeyID,
		secretAccessKey,
		region,
		keyIdentifierConfigName,
		keyIdentifierConfigValue)
}

func getKeyIdentifierFile(t *testing.T) string {
	tempDir := t.TempDir()
	tempFilePath := path.Join(tempDir, validServerIDFile)
	err := os.WriteFile(tempFilePath, []byte(validServerID), 0o600)
	if err != nil {
		t.Error(err)
	}
	if isWindows {
		tempFilePath = filepath.ToSlash(tempFilePath)
	}
	return tempFilePath
}

func getEmptyKeyIdentifierFile(t *testing.T) string {
	tempDir := t.TempDir()
	keyIdentifierFile := path.Join(tempDir, validServerIDFile)
	if isWindows {
		keyIdentifierFile = filepath.ToSlash(keyIdentifierFile)
	}
	return keyIdentifierFile
}

func getCustomPolicyFile(t *testing.T) string {
	tempDir := t.TempDir()
	tempFilePath := path.Join(tempDir, validPolicyFile)
	err := os.WriteFile(tempFilePath, []byte(customPolicy), 0o600)
	if err != nil {
		t.Error(err)
	}
	if isWindows {
		tempFilePath = filepath.ToSlash(tempFilePath)
	}
	return tempFilePath
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
