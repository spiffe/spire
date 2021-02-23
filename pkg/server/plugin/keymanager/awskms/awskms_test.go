package awskms

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/suite"
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

func TestKeyManager(t *testing.T) {
	suite.Run(t, new(KmsPluginSuite))
}

type KmsPluginSuite struct {
	spiretest.Suite
	kmsClientFake *kmsClientFake
	rawPlugin     *Plugin
	// The plugin under test
	plugin keymanager.Plugin
}

func (ps *KmsPluginSuite) SetupTest() {
	ps.kmsClientFake = &kmsClientFake{t: ps.T()}

	// Setup plugin
	plugin := newPlugin(func(c *Config) (kmsClient, error) {
		return ps.kmsClientFake, nil
	})

	plugin.SetLogger(hclog.NewNullLogger())
	plugin.kmsClient = ps.kmsClientFake
	ps.rawPlugin = plugin
	ps.plugin = plugin
}

func (ps *KmsPluginSuite) reset() {
	ps.kmsClientFake.expectedCreateKeyInput = nil
	ps.kmsClientFake.createKeyOutput = nil
	ps.kmsClientFake.createKeyErr = nil
	ps.kmsClientFake.expectedDescribeKeyInput = nil
	ps.kmsClientFake.describeKeyOutput = nil
	ps.kmsClientFake.describeKeyErr = nil
	ps.kmsClientFake.expectedGetPublicKeyInput = nil
	ps.kmsClientFake.getPublicKeyOutput = nil
	ps.kmsClientFake.getPublicKeyErr = nil
	ps.kmsClientFake.expectedListAliasesInput = nil
	ps.kmsClientFake.listAliasesOutput = nil
	ps.kmsClientFake.listAliasesErr = nil
	ps.kmsClientFake.expectedListKeysInput = nil
	ps.kmsClientFake.listKeysOutput = nil
	ps.kmsClientFake.listKeysErr = nil
	ps.kmsClientFake.expectedScheduleKeyDeletionInput = nil
	ps.kmsClientFake.scheduleKeyDeletionOutput = nil
	ps.kmsClientFake.scheduleKeyDeletionErr = nil
	ps.kmsClientFake.expectedSignInput = nil
	ps.kmsClientFake.signOutput = nil
	ps.kmsClientFake.signErr = nil
	ps.rawPlugin.entries = map[string]keyEntry{}
}

// Test Configure

func (ps *KmsPluginSuite) Test_Configure() {
	for _, tt := range []struct {
		name            string
		expectedErr     string
		expectedEntries map[string]keyEntry

		configureRequest *plugin.ConfigureRequest

		// setupListAliases
		aliases        []types.AliasListEntry
		listAliasesErr string

		// setupDescribeKey
		describeKeySpec types.CustomerMasterKeySpec
		describeKeyErr  string

		// setupGetPublicKey
		getPublicKeyErr string
	}{

		{
			name:             "pass",
			configureRequest: ps.configureRequestWithDefaults(),
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
			describeKeySpec: types.CustomerMasterKeySpecRsa4096,
			expectedEntries: map[string]keyEntry{
				spireKeyID: {
					KMSKeyID: kmsKeyID,
					PublicKey: &keymanager.PublicKey{
						Id:   spireKeyID,
						Type: keymanager.KeyType_RSA_4096,
					},
				},
			},
		},
		{
			name: "missing access key id",
			configureRequest: ps.configureRequestWith(`{
				 		"secret_access_key":"secret_access_key",
				 		"region":"region"
					 }`),
			aliases: []types.AliasListEntry{},
		},
		{
			name: "missing secret access key",
			configureRequest: ps.configureRequestWith(`{
				 		"access_key_id":"access_key",
				 		"region":"region"
					 }`),
			aliases: []types.AliasListEntry{},
		},
		{
			name: "missing region",
			configureRequest: ps.configureRequestWith(`{
				 		"access_key_id":"access_key",
				 		"secret_access_key":"secret_access_key",
				 	}`),
			expectedErr: "awskms: configuration is missing a region",
		},
		{
			name:             "decode error",
			configureRequest: ps.configureRequestWith("{ malformed json }"),
			expectedErr:      "awskms: unable to decode configuration: 1:11: illegal char",
		},
		{
			name:             "list aliases error",
			expectedErr:      "awskms: failed to fetch keys: fake list aliases error",
			configureRequest: ps.configureRequestWithDefaults(),
			listAliasesErr:   "fake list aliases error",
		},
		{
			name:             "describe key error",
			expectedErr:      "awskms: failed to process KMS key: awskms: failed to describe key: describe key error",
			configureRequest: ps.configureRequestWithDefaults(),
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
			describeKeySpec: types.CustomerMasterKeySpecRsa4096,
			describeKeyErr:  "describe key error",
		},
		{
			name:             "unsupported key error",
			configureRequest: ps.configureRequestWithDefaults(),
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
			describeKeySpec: "unsupported key spec",
		},
		{
			name:             "get public key error",
			expectedErr:      "awskms: failed to process KMS key: awskms: failed to get public key: get public key error",
			configureRequest: ps.configureRequestWithDefaults(),
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
			describeKeySpec: types.CustomerMasterKeySpecRsa4096,
			getPublicKeyErr: "get public key error",
		},
	} {
		tt := tt
		t := ps.T()
		t.Run(tt.name, func(t *testing.T) {
			ps.reset()
			ps.setupListAliases(tt.aliases, tt.listAliasesErr)
			ps.setupDescribeKey(tt.describeKeySpec, tt.describeKeyErr)
			ps.setupGetPublicKey(tt.getPublicKeyErr)

			_, err := ps.plugin.Configure(ctx, tt.configureRequest)

			if tt.expectedErr != "" {
				ps.Require().Error(err)
				ps.Require().Equal(tt.expectedErr, err.Error())
				return
			}

			ps.Require().NoError(err)
			ps.Require().Len(ps.rawPlugin.entries, len(tt.expectedEntries))

			for k, v := range tt.expectedEntries {
				ps.Require().Equal(v.KMSKeyID, ps.rawPlugin.entries[k].KMSKeyID)
				ps.Require().Equal(v.PublicKey.Id, ps.rawPlugin.entries[k].PublicKey.Id)
				ps.Require().Equal(v.PublicKey.Type, ps.rawPlugin.entries[k].PublicKey.Type)
			}
		})
	}
}

func (ps *KmsPluginSuite) Test_GenerateKey() {
	for _, tt := range []struct {
		name                   string
		err                    string
		expectedEntries        map[string]keyEntry
		aliases                []types.AliasListEntry
		keyType                keymanager.KeyType
		keySpec                string
		publicKey              string
		createKeyErr           string
		getPublicKeyErr        string
		scheduleKeyDeletionErr string
	}{
		{
			name: "non existing key",
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
			expectedEntries: map[string]keyEntry{
				spireKeyID: {
					KMSKeyID: kmsKeyID,
					PublicKey: &keymanager.PublicKey{
						Id:   spireKeyID,
						Type: keymanager.KeyType_RSA_4096,
					},
				},
			},
		},
		{
			name: "replace old key",
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
			expectedEntries: map[string]keyEntry{
				spireKeyID: {
					KMSKeyID: kmsKeyID,
					PublicKey: &keymanager.PublicKey{
						Id:   spireKeyID,
						Type: keymanager.KeyType_RSA_4096,
					},
				},
			},
		},
		{
			name:    "unsupported key spec",
			keyType: keymanager.KeyType_RSA_1024,
			err:     "awskms: unsupported key type: KeyType_RSA_1024",
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
		{
			name:         "create key error",
			err:          "awskms: failed to create key: fake key",
			createKeyErr: "fake key",
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
		{
			name:            "get public key error",
			err:             "awskms: failed to get public key: public key error",
			getPublicKeyErr: "public key error",
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
		{
			name:                   "schedule key deletion error",
			scheduleKeyDeletionErr: "schedule key deletion error",
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
			expectedEntries: map[string]keyEntry{
				spireKeyID: {
					KMSKeyID: kmsKeyID,
					PublicKey: &keymanager.PublicKey{
						Id:   spireKeyID,
						Type: keymanager.KeyType_RSA_4096,
					},
				},
			},
		},
	} {
		tt := tt
		t := ps.T()
		t.Run(tt.name, func(t *testing.T) {
			ps.reset()
			ps.setupScheduleKeyDeletion("")
			ps.setupListAliases(tt.aliases, "")
			ps.setupDescribeKey(types.CustomerMasterKeySpecRsa4096, "")
			ps.setupCreateKey(types.CustomerMasterKeySpecRsa4096, tt.createKeyErr)
			ps.setupGetPublicKey("")

			_, err := ps.plugin.Configure(ctx, ps.configureRequestWithDefaults())
			ps.Require().NoError(err)

			ps.setupGetPublicKey(tt.getPublicKeyErr)

			keyType := keymanager.KeyType_RSA_4096
			if tt.keyType != keymanager.KeyType_UNSPECIFIED_KEY_TYPE {
				keyType = tt.keyType
			}

			_, err = ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
				KeyId:   spireKeyID,
				KeyType: keyType,
			})

			if tt.err != "" {
				ps.Require().Error(err)
				ps.Require().Equal(err.Error(), tt.err)

				return
			}

			ps.Require().NoError(err)
			ps.Require().Equal(len(tt.expectedEntries), len(ps.rawPlugin.entries))

			for k, v := range tt.expectedEntries {
				ps.Require().Equal(v.KMSKeyID, ps.rawPlugin.entries[k].KMSKeyID)
				ps.Require().Equal(v.PublicKey.Id, ps.rawPlugin.entries[k].PublicKey.Id)
				ps.Require().Equal(v.PublicKey.Type, ps.rawPlugin.entries[k].PublicKey.Type)
			}
		})
	}
}

func (ps *KmsPluginSuite) Test_SignData() {
	for _, tt := range []struct {
		name string
		err  string

		aliases       []types.AliasListEntry
		signDataError string
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
		{
			name:    "non existing key",
			err:     fmt.Sprintf("awskms: no such key \"%s\"", spireKeyID),
			aliases: []types.AliasListEntry{},
		},
		{
			name:          "sign error",
			err:           "awskms: failed to sign: sign error",
			signDataError: "sign error",
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
	} {
		tt := tt
		t := ps.T()
		t.Run(tt.name, func(t *testing.T) {
			ps.reset()
			ps.setupListAliases(tt.aliases, "")
			ps.setupSignData(tt.signDataError)
			ps.setupDescribeKey(types.CustomerMasterKeySpecRsa4096, "")
			ps.setupGetPublicKey("")

			_, err := ps.plugin.Configure(ctx, ps.configureRequestWithDefaults())
			ps.Require().NoError(err)

			resp, err := ps.plugin.SignData(ctx, &keymanager.SignDataRequest{
				KeyId: spireKeyID,
				Data:  []byte("data"),
				SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
					HashAlgorithm: keymanager.HashAlgorithm_SHA256,
				},
			})

			if tt.err != "" {
				ps.Require().Error(err)
				ps.Require().Equal(err.Error(), tt.err)

				return
			}
			ps.Require().NotNil(resp)
			ps.Require().NoError(err)
		})
	}
}

func (ps *KmsPluginSuite) Test_GetPublicKey() {
	for _, tt := range []struct {
		name string
		err  string

		aliases []types.AliasListEntry
		keyID   string
	}{
		{
			name:  "existing key",
			keyID: spireKeyID,
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
		{
			name:    "non existing key",
			err:     "awskms: no such key \"spireKeyID\"",
			keyID:   spireKeyID,
			aliases: []types.AliasListEntry{},
		},
		{
			name:    "missing key id",
			err:     "awskms: key id is required",
			aliases: []types.AliasListEntry{},
		},
	} {
		tt := tt
		t := ps.T()
		t.Run(tt.name, func(t *testing.T) {
			ps.reset()
			ps.setupListAliases(tt.aliases, "")
			ps.setupDescribeKey(types.CustomerMasterKeySpecRsa4096, "")
			ps.setupGetPublicKey("")

			_, err := ps.plugin.Configure(ctx, ps.configureRequestWithDefaults())
			ps.Require().NoError(err)

			resp, err := ps.plugin.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
				KeyId: tt.keyID,
			})

			if tt.err != "" {
				ps.Require().Error(err)
				ps.Require().Equal(err.Error(), tt.err)

				return
			}
			ps.Require().NotNil(resp)
			ps.Require().NoError(err)
		})
	}
}
func (ps *KmsPluginSuite) Test_GetPublicKeys() {
	for _, tt := range []struct {
		name string
		err  string

		aliases []types.AliasListEntry
	}{
		{
			name: "existing key",
			aliases: []types.AliasListEntry{
				{
					AliasName:   aws.String(kmsAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
		{
			name:    "non existing key",
			aliases: []types.AliasListEntry{},
		},
	} {
		tt := tt
		t := ps.T()
		t.Run(tt.name, func(t *testing.T) {
			ps.reset()
			ps.setupListAliases(tt.aliases, "")
			ps.setupDescribeKey(types.CustomerMasterKeySpecRsa4096, "")
			ps.setupGetPublicKey("")

			_, err := ps.plugin.Configure(ctx, ps.configureRequestWithDefaults())
			ps.Require().NoError(err)

			resp, err := ps.plugin.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})

			if tt.err != "" {
				ps.Require().Error(err)
				ps.Require().Equal(err.Error(), tt.err)

				return
			}

			ps.Require().NotNil(resp)
			ps.Require().NoError(err)

			ps.Require().Equal(len(tt.aliases), len(resp.PublicKeys))
		})
	}
}
func (ps *KmsPluginSuite) Test_GetPluginInfo() {
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
		t := ps.T()
		t.Run(tt.name, func(t *testing.T) {
			ps.reset()

			resp, err := ps.plugin.GetPluginInfo(ctx, &plugin.GetPluginInfoRequest{})

			ps.Require().NotNil(resp)
			ps.Require().NoError(err)
		})
	}
}

func (ps *KmsPluginSuite) configureRequestWith(config string) *plugin.ConfigureRequest {
	return &plugin.ConfigureRequest{
		Configuration: config,
	}
}

func (ps *KmsPluginSuite) configureRequestWithDefaults() *plugin.ConfigureRequest {
	return &plugin.ConfigureRequest{
		Configuration: ps.serializedConfiguration(validAccessKeyID, validSecretAccessKey, validRegion),
	}
}

func (ps *KmsPluginSuite) serializedConfiguration(accessKeyID, secretAccessKey, region string) string {
	return fmt.Sprintf(`{
		"access_key_id": "%s",
		"secret_access_key": "%s",
		"region":"%s"
		}`,
		accessKeyID,
		secretAccessKey,
		region)
}

func (ps *KmsPluginSuite) setupListAliases(aliases []types.AliasListEntry, fakeError string) {
	ps.kmsClientFake.expectedListAliasesInput = &kms.ListAliasesInput{}

	if fakeError != "" {
		ps.kmsClientFake.listAliasesErr = errors.New(fakeError)
	}

	if aliases != nil {
		ps.kmsClientFake.listAliasesOutput = &kms.ListAliasesOutput{
			Aliases: aliases,
		}
	}
}

func (ps *KmsPluginSuite) setupDescribeKey(keySpec types.CustomerMasterKeySpec, fakeError string) {
	km := &types.KeyMetadata{
		KeyId:                 aws.String(kmsKeyID),
		Description:           aws.String(defaultKeyPrefix + spireKeyID),
		CustomerMasterKeySpec: keySpec,
		Enabled:               true,
		CreationDate:          aws.Time(time.Now()),
	}

	ps.kmsClientFake.expectedDescribeKeyInput = &kms.DescribeKeyInput{KeyId: aws.String(kmsAlias)}
	ps.kmsClientFake.describeKeyOutput = &kms.DescribeKeyOutput{KeyMetadata: km}
	if fakeError != "" {
		ps.kmsClientFake.describeKeyErr = errors.New(fakeError)
	}
}

func (ps *KmsPluginSuite) setupGetPublicKey(fakeError string) {
	var data string

	for n := 0; n < 4096; n++ {
		data += "*"
	}

	pub := &kms.GetPublicKeyOutput{
		CustomerMasterKeySpec: types.CustomerMasterKeySpecEccNistP256,
		KeyId:                 aws.String(kmsKeyID),
		KeyUsage:              types.KeyUsageTypeSignVerify,
		PublicKey:             []byte(data),
		SigningAlgorithms:     []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecRsassaPssSha256},
	}

	ps.kmsClientFake.expectedGetPublicKeyInput = &kms.GetPublicKeyInput{KeyId: aws.String(kmsAlias)}
	if fakeError != "" {
		ps.kmsClientFake.getPublicKeyErr = errors.New(fakeError)
	}

	ps.kmsClientFake.getPublicKeyOutput = pub
}

func (ps *KmsPluginSuite) setupCreateKey(keySpec types.CustomerMasterKeySpec, fakeError string) {
	desc := aws.String(defaultKeyPrefix + spireKeyID)
	ku := types.KeyUsageTypeSignVerify
	ks := keySpec

	ps.kmsClientFake.expectedCreateKeyInput = &kms.CreateKeyInput{
		Description:           desc,
		KeyUsage:              ku,
		CustomerMasterKeySpec: ks,
	}

	if fakeError != "" {
		ps.kmsClientFake.createKeyErr = errors.New(fakeError)
	}

	km := &types.KeyMetadata{
		KeyId:                 aws.String(kmsKeyID),
		CreationDate:          aws.Time(time.Now()),
		Description:           desc,
		KeyUsage:              ku,
		CustomerMasterKeySpec: ks,
	}
	ps.kmsClientFake.createKeyOutput = &kms.CreateKeyOutput{KeyMetadata: km}
}

func (ps *KmsPluginSuite) setupScheduleKeyDeletion(fakeError string) {
	ps.kmsClientFake.expectedScheduleKeyDeletionInput = &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(kmsKeyID),
		PendingWindowInDays: aws.Int32(7),
	}

	if fakeError != "" {
		ps.kmsClientFake.scheduleKeyDeletionErr = errors.New(fakeError)
	}

	ps.kmsClientFake.scheduleKeyDeletionOutput = &kms.ScheduleKeyDeletionOutput{
		KeyId:        aws.String(kmsKeyID),
		DeletionDate: aws.Time(time.Now()),
	}
}

func (ps *KmsPluginSuite) setupSignData(fakeError string) {
	ps.kmsClientFake.expectedSignInput = &kms.SignInput{
		KeyId:            aws.String(kmsKeyID),
		Message:          []byte("data"),
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	}

	if fakeError != "" {
		ps.kmsClientFake.signErr = errors.New(fakeError)
	}

	ps.kmsClientFake.signOutput = &kms.SignOutput{
		Signature: []byte("signature"),
	}
}
