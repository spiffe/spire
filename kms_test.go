package kms

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/stretchr/testify/suite"
)

const (
	// Defaults used for testing
	validAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	validSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	validRegion          = "us-west-2"
	kmsKeyID             = "kmsKeyID"
	spireKeyID           = "spireKeyID"
)

var (
	ctx           = context.Background()
	spireKeyAlias = fmt.Sprintf("%s%s", keyPrefix, spireKeyID)
)

func TestKeyManager(t *testing.T) {
	suite.Run(t, new(KmsPluginSuite))
}

type KmsPluginSuite struct {
	// spiretest.Suite
	suite.Suite

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

func (ps *KmsPluginSuite) Test_Configures() {
	for _, tt := range []struct {
		name            string
		expectedErr     string
		expectedEntries map[string]keyEntry

		configureRequest *plugin.ConfigureRequest

		// setupListAliases
		aliases        []*kms.AliasListEntry
		listAliasesErr string

		// setupDescribeKey
		describeKeySpec string
		describeKeyErr  string

		// setupGetPublicKey
		getPublicKeyErr string
	}{

		{
			name:             "pass",
			configureRequest: ps.configureRequestWithDefaults(),
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
			describeKeySpec: kms.CustomerMasterKeySpecRsa4096,
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
			name: "missing access key",
			configureRequest: ps.configureRequestWith(`{
				 		"secret_access_key":"secret_access_key",
				 		"region":"region"
					 }`),
			expectedErr: "kms: configuration is missing an access key id",
		},
		{
			name: "missing secret access key",
			configureRequest: ps.configureRequestWith(`{
				 		"access_key_id":"access_key",
				 		"region":"region"
				 	}`),
			expectedErr: "kms: configuration is missing a secret access key",
		},
		{
			name: "missing region",
			configureRequest: ps.configureRequestWith(`{
				 		"access_key_id":"access_key",
				 		"secret_access_key":"secret_access_key",
				 	}`),
			expectedErr: "kms: configuration is missing a region",
		},
		{
			name:             "decore error",
			configureRequest: ps.configureRequestWith("{ malformed json }"),
			expectedErr:      "kms: unable to decode configuration: 1:11: illegal char",
		},
		{
			name:             "list aliases error",
			expectedErr:      "kms: failed to fetch keys: fake list aliases error",
			configureRequest: ps.configureRequestWithDefaults(),
			listAliasesErr:   "fake list aliases error",
		},
		{
			name:             "describe key error",
			expectedErr:      "kms: failed to process KMS key: kms: failed to describe key: describe key error",
			configureRequest: ps.configureRequestWithDefaults(),
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
			describeKeySpec: kms.CustomerMasterKeySpecRsa4096,
			describeKeyErr:  "describe key error",
		},
		{
			name:             "unsupported key error",
			configureRequest: ps.configureRequestWithDefaults(),
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
			describeKeySpec: "unsupported key spec",
		},
		{
			name:             "get public key error",
			expectedErr:      "kms: failed to process KMS key: kms: failed to get public key: get public key error",
			configureRequest: ps.configureRequestWithDefaults(),
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
			describeKeySpec: kms.CustomerMasterKeySpecRsa4096,
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
				ps.Require().Equal(err.Error(), tt.expectedErr)
				ps.Require().Equal(err.Error(), tt.expectedErr)

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

func (ps *KmsPluginSuite) Test_GenerateKey() {
	for _, tt := range []struct {
		name                   string
		err                    string
		expectedEntries        map[string]keyEntry
		aliases                []*kms.AliasListEntry
		keyType                keymanager.KeyType
		keySpec                string
		publicKey              string
		createKeyErr           string
		getPublicKeyErr        string
		scheduleKeyDeletionErr string
	}{
		{
			name: "non existing key",
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
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
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
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
			err:     "kms: unsupported key type: KeyType_RSA_1024",
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
		{
			name:         "create key error",
			err:          "kms: failed to create key: fake key",
			createKeyErr: "fake key",
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
		{
			name:            "get public key error",
			err:             "kms: failed to get public key: public key error",
			getPublicKeyErr: "public key error",
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
		{
			name:                   "schedule key deletion error",
			scheduleKeyDeletionErr: "schedule key deletion error",
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
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
		t := ps.T()
		t.Run(tt.name, func(t *testing.T) {
			ps.reset()
			ps.setupScheduleKeyDeletion("")
			ps.setupListAliases(tt.aliases, "")
			ps.setupDescribeKey(kms.CustomerMasterKeySpecRsa4096, "")
			ps.setupCreateKey(kms.CustomerMasterKeySpecRsa4096, tt.createKeyErr)
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

		aliases       []*kms.AliasListEntry
		signDataError string
	}{
		{
			name: "pass",
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
		{
			name:    "non existing key",
			err:     fmt.Sprintf("kms: no such key \"%s\"", spireKeyID),
			aliases: []*kms.AliasListEntry{},
		},
		{
			name:          "sign error",
			err:           "kms: failed to sign: sign error",
			signDataError: "sign error",
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
	} {
		t := ps.T()
		t.Run(tt.name, func(t *testing.T) {
			ps.reset()
			ps.setupListAliases(tt.aliases, "")
			ps.setupSignData(tt.signDataError)
			ps.setupDescribeKey(kms.CustomerMasterKeySpecRsa4096, "")
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

		aliases []*kms.AliasListEntry
		keyID   string
	}{
		{
			name:  "existing key",
			keyID: spireKeyID,
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
		{
			name:    "non existing key",
			err:     "kms: no such key \"spireKeyID\"",
			keyID:   spireKeyID,
			aliases: []*kms.AliasListEntry{},
		},
		{
			name:    "missing key id",
			err:     "kms: key id is required",
			aliases: []*kms.AliasListEntry{},
		},
	} {
		t := ps.T()
		t.Run(tt.name, func(t *testing.T) {
			ps.reset()
			ps.setupListAliases(tt.aliases, "")
			ps.setupDescribeKey(kms.CustomerMasterKeySpecRsa4096, "")
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

		aliases []*kms.AliasListEntry
	}{
		{
			name: "existing key",
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
		{
			name:    "non existing key",
			aliases: []*kms.AliasListEntry{},
		},
	} {
		t := ps.T()
		t.Run(tt.name, func(t *testing.T) {
			ps.reset()
			ps.setupListAliases(tt.aliases, "")
			ps.setupDescribeKey(kms.CustomerMasterKeySpecRsa4096, "")
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

		aliases []*kms.AliasListEntry
	}{
		{
			name: "pass",
			aliases: []*kms.AliasListEntry{
				{
					AliasName:   aws.String(spireKeyAlias),
					TargetKeyId: aws.String(kmsKeyID),
				},
			},
		},
	} {
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

func (ps *KmsPluginSuite) setupListAliases(aliases []*kms.AliasListEntry, fakeError string) {
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

func (ps *KmsPluginSuite) setupDescribeKey(keySpec string, fakeError string) {
	km := &kms.KeyMetadata{
		KeyId:                 aws.String(kmsKeyID),
		Description:           aws.String(keyPrefix + spireKeyID),
		CustomerMasterKeySpec: aws.String(keySpec),
		Enabled:               aws.Bool(true),
		CreationDate:          aws.Time(time.Now()),
	}

	ps.kmsClientFake.expectedDescribeKeyInput = &kms.DescribeKeyInput{KeyId: aws.String(kmsKeyID)}
	ps.kmsClientFake.describeKeyOutput = &kms.DescribeKeyOutput{KeyMetadata: km}
	if fakeError != "" {
		ps.kmsClientFake.describeKeyErr = errors.New(fakeError)
	}
}

func (ps *KmsPluginSuite) setupGetPublicKey(fakeError string) {
	var data string

	for n := 0; n < 4096; n++ {
		data = data + "*"
	}

	pub := &kms.GetPublicKeyOutput{
		CustomerMasterKeySpec: aws.String(kms.CustomerMasterKeySpecEccNistP256),
		KeyId:                 aws.String(kmsKeyID),
		KeyUsage:              aws.String(signVerifyKeyUsage),
		PublicKey:             []byte(data),
		SigningAlgorithms:     []*string{aws.String(kms.SigningAlgorithmSpecRsassaPssSha256)},
	}

	ps.kmsClientFake.expectedGetPublicKeyInput = &kms.GetPublicKeyInput{KeyId: aws.String(kmsKeyID)}
	if fakeError != "" {
		ps.kmsClientFake.getPublicKeyErr = errors.New(fakeError)
	}

	ps.kmsClientFake.getPublicKeyOutput = pub
}

func (ps *KmsPluginSuite) setupCreateKey(keySpec string, fakeError string) {
	desc := aws.String(keyPrefix + spireKeyID)
	ku := aws.String(kms.KeyUsageTypeSignVerify)
	ks := aws.String(keySpec)

	ps.kmsClientFake.expectedCreateKeyInput = &kms.CreateKeyInput{
		Description:           desc,
		KeyUsage:              ku,
		CustomerMasterKeySpec: ks,
	}

	if fakeError != "" {
		ps.kmsClientFake.createKeyErr = errors.New(fakeError)
	}

	km := &kms.KeyMetadata{
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
		PendingWindowInDays: aws.Int64(7),
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
		KeyId:            aws.String(spireKeyAlias),
		Message:          []byte("data"),
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: aws.String(kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256),
	}

	if fakeError != "" {

		ps.kmsClientFake.signErr = errors.New(fakeError)
	}

	ps.kmsClientFake.signOutput = &kms.SignOutput{
		Signature: []byte("signature"),
	}
}
