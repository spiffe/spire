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
	awsKeyID             = "awsKeyID"
	spireKeyID           = "spireKeyID"
)

var (
	ctx = context.Background()
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

	plugin.SetLogger(hclog.Default())
	plugin.kmsClient = ps.kmsClientFake
	ps.rawPlugin = plugin
	ps.plugin = plugin
}

func (ps *KmsPluginSuite) Test_Configure() {
	// Should return a list of keys
	ps.verifyListKeys(true, nil)

	// Should return Key metadata
	ps.verifyDescribeKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return Key publicKey
	ps.verifyGetPublicKey(nil)

	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())
	ps.Require().NoError(err)
	ps.Require().Equal(1, len(ps.rawPlugin.entries))
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].AwsKeyID, awsKeyID)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Type, keymanager.KeyType_RSA_4096)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Id, spireKeyID)
}

func (ps *KmsPluginSuite) Test_Configure_Invalid_Config() {
	// Missing Access Key Id
	invalidConfig := `{
		"secret_access_key":"secret_access_key",
		"region":"region"
	}`
	_, err := ps.plugin.Configure(ctx, ps.configureRequest(invalidConfig))
	ps.Require().Error(err)

	//Mission Secret Access Key
	invalidConfig = `{
		"access_key_id":"access_key",
		"region":"region"
	}`
	_, err = ps.plugin.Configure(ctx, ps.configureRequest(invalidConfig))
	ps.Assert().Error(err)

	// Missing region
	invalidConfig = `{
		"access_key_id":"access_key",
		"secret_access_key":"secret_access_key",
	}`
	_, err = ps.plugin.Configure(ctx, ps.configureRequest(invalidConfig))
	ps.Assert().Error(err)
}

func (ps *KmsPluginSuite) Test_Configure_DecodeError() {
	malformedConfig := `{
		badjson
	}`
	_, err := ps.plugin.Configure(ctx, ps.configureRequest(malformedConfig))
	ps.Require().Error(err)
}

func (ps *KmsPluginSuite) Test_Configure_ListKeysError() {
	var errMsg = "List Keys error"

	// ListKeys response should error
	ps.verifyListKeys(true, errors.New(errMsg))

	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), errMsg)
}

func (ps *KmsPluginSuite) Test_Configure_DescribeKeyError() {
	// Should return a list of keys
	ps.verifyListKeys(true, nil)

	// Response should error
	ps.verifyDescribeKey(kms.CustomerMasterKeySpecRsa4096, errors.New("Describe Key error"))

	// An error response while calling describeKey only prevents the key to be included into the internal keys storage
	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())
	ps.Require().NoError(err)
	ps.Require().Equal(0, len(ps.rawPlugin.entries))
}

func (ps *KmsPluginSuite) Test_Configure_UnsupportedKeySpecError() {
	// Should return a list of keys
	ps.verifyListKeys(true, nil)

	// Response should include an unsupported KeySpec
	ps.verifyDescribeKey("Unsupported keySpec", nil)

	// An error processing keySpec only prevents the key to be included into the internal keys storage
	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())

	ps.Require().NoError(err)
	ps.Require().Equal(0, len(ps.rawPlugin.entries))
}

func (ps *KmsPluginSuite) Test_Configure_GetPublicKeyError() {
	var errMsg = "Get Public Key error"

	// Should return a list of keys
	ps.verifyListKeys(true, nil)

	// Should return Key metadata
	ps.verifyDescribeKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Response should error
	ps.verifyGetPublicKey(errors.New(errMsg))

	// An error response while calling getPublicKey only prevents the key to be included into the internal keys storage
	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())
	ps.Require().NoError(err)
	ps.Require().Equal(0, len(ps.rawPlugin.entries))
}

func (ps *KmsPluginSuite) Test_GenerateKey_NonExistingKey() {
	ps.configurePluginWithOutKeys()

	// Should return new created Key
	ps.verifyCreateKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return Key publicKey
	ps.verifyGetPublicKey(nil)

	_, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_4096,
	})
	ps.Require().NoError(err)
	ps.Require().Equal(1, len(ps.rawPlugin.entries))
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].AwsKeyID, awsKeyID)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Type, keymanager.KeyType_RSA_4096)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Id, spireKeyID)
}

func (ps *KmsPluginSuite) Test_GenerateKey_ReplaceOldKey() {
	ps.configurePluginWithExistingKeys()

	// Should return new created Key
	ps.verifyCreateKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return Key publicKey
	ps.verifyGetPublicKey(nil)

	// Should Schedule key for deletion
	ps.verifyScheduleKeyDeletion(nil)

	_, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_4096,
	})
	ps.Require().NoError(err)
	ps.Require().Equal(1, len(ps.rawPlugin.entries))
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].AwsKeyID, awsKeyID)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Type, keymanager.KeyType_RSA_4096)
	ps.Require().Equal(ps.rawPlugin.entries[spireKeyID].PublicKey.Id, spireKeyID)
}

func (ps *KmsPluginSuite) Test_GenerateKey_UnsupportedKeySpecError() {
	ps.configurePluginWithExistingKeys()

	_, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_1024,
	})
	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), "kms: unsupported")
}

func (ps *KmsPluginSuite) Test_GenerateKey_KmsCreateKeyError() {
	ps.configurePluginWithExistingKeys()

	var errMsg = "Create Key Error"

	// Response should error
	ps.verifyCreateKey(kms.CustomerMasterKeySpecRsa4096, errors.New(errMsg))

	_, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_4096,
	})

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), errMsg)
}

func (ps *KmsPluginSuite) Test_GenerateKey_GetPublicKeyError() {
	ps.configurePluginWithExistingKeys()

	var errMsg = "Get Public Key Error"

	// Should create the new key
	ps.verifyCreateKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Response should error
	ps.verifyGetPublicKey(errors.New(errMsg))

	_, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_4096,
	})
	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), errMsg)
}

func (ps *KmsPluginSuite) Test_GenerateKey_ScheduleKeyDeletionError() {
	ps.configurePluginWithExistingKeys()

	var errMsg = "Schedule Key Deletion Error"

	// Should create the new key
	ps.verifyCreateKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return key Public Key
	ps.verifyGetPublicKey(nil)

	// Response should error
	ps.verifyScheduleKeyDeletion(errors.New(errMsg))

	_, err := ps.plugin.GenerateKey(ctx, &keymanager.GenerateKeyRequest{
		KeyId:   spireKeyID,
		KeyType: keymanager.KeyType_RSA_4096,
	})
	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), errMsg)
}

func (ps *KmsPluginSuite) Test_SignData() {
	ps.configurePluginWithExistingKeys()

	// Should sign data
	ps.verifySignData(nil)

	resp, err := ps.plugin.SignData(ctx, &keymanager.SignDataRequest{
		KeyId: spireKeyID,
		Data:  []byte("data"),
		SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanager.HashAlgorithm_SHA256,
		},
	})

	ps.Require().NoError(err)
	ps.Require().NotNil(resp)
	ps.Require().Equal(resp.Signature, []byte("signature"))
}

func (ps *KmsPluginSuite) Test_SignData_NoExistingKeyError() {
	ps.configurePluginWithOutKeys()

	_, err := ps.plugin.SignData(ctx, &keymanager.SignDataRequest{
		KeyId: spireKeyID,
		Data:  []byte("data"),
	})

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), "kms: unable to find KeyId: "+spireKeyID)
}

func (ps *KmsPluginSuite) Test_SignData_SignError() {
	ps.configurePluginWithExistingKeys()

	var errMsg = "Sign Data Error"

	// Response should error
	ps.verifySignData(errors.New(errMsg))

	_, err := ps.plugin.SignData(ctx, &keymanager.SignDataRequest{
		KeyId: spireKeyID,
		Data:  []byte("data"),
		SignerOpts: &keymanager.SignDataRequest_HashAlgorithm{
			HashAlgorithm: keymanager.HashAlgorithm_SHA256,
		},
	})

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), errMsg)
}

func (ps *KmsPluginSuite) Test_GetPublicKey_ExistingKey() {
	ps.configurePluginWithExistingKeys()

	resp, err := ps.plugin.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: spireKeyID,
	})

	ps.Require().NoError(err)
	ps.Require().Equal(resp.PublicKey.Id, ps.rawPlugin.entries[spireKeyID].PublicKey.Id)
	ps.Require().Equal(resp.PublicKey.Type, ps.rawPlugin.entries[spireKeyID].PublicKey.Type)
	ps.Require().Equal(resp.PublicKey.PkixData, ps.rawPlugin.entries[spireKeyID].PublicKey.PkixData)
}

func (ps *KmsPluginSuite) Test_GetPublicKey_NotExistingKey() {
	ps.configurePluginWithOutKeys()

	resp, err := ps.plugin.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: spireKeyID,
	})

	ps.Require().NoError(err)
	ps.Require().Nil(resp.PublicKey)
}

func (ps *KmsPluginSuite) Test_GetPublicKey_MissingKeyID() {
	ps.configurePluginWithOutKeys()

	_, err := ps.plugin.GetPublicKey(ctx, &keymanager.GetPublicKeyRequest{
		KeyId: "",
	})

	ps.Require().Error(err)
	ps.Require().Equal(err.Error(), "kms: KeyId is required")
}

func (ps *KmsPluginSuite) Test_GetPublicKeys_ExistingKeys() {
	ps.configurePluginWithExistingKeys()

	resp, err := ps.plugin.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})

	ps.Require().NoError(err)
	ps.Require().Equal(len(ps.rawPlugin.entries), len(resp.PublicKeys))
}

func (ps *KmsPluginSuite) Test_GetPublicKeys_NotExistingKey() {
	ps.configurePluginWithOutKeys()

	resp, err := ps.plugin.GetPublicKeys(ctx, &keymanager.GetPublicKeysRequest{})

	ps.Require().NoError(err)
	ps.Require().Equal(len(ps.rawPlugin.entries), len(resp.PublicKeys))
	ps.Require().Equal(0, len(resp.PublicKeys))
}

func (ps *KmsPluginSuite) Test_GetPluginInfo() {
	ps.configurePluginWithOutKeys()

	resp, err := ps.plugin.GetPluginInfo(ctx, &plugin.GetPluginInfoRequest{})

	ps.Require().NoError(err)
	ps.Require().NotNil(resp)
}

// helper methods
func (ps *KmsPluginSuite) configurePluginWithExistingKeys() {
	ps.configurePlugin(true)
}

func (ps *KmsPluginSuite) configurePluginWithOutKeys() {
	ps.configurePlugin(false)
}

func (ps *KmsPluginSuite) configurePlugin(existingKeys bool) {
	// Should return a list of keys
	ps.verifyListKeys(existingKeys, nil)

	// Should return Key metadata
	ps.verifyDescribeKey(kms.CustomerMasterKeySpecRsa4096, nil)

	// Should return Key publicKey
	ps.verifyGetPublicKey(nil)

	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())
	ps.Require().NoError(err)
}

func (ps *KmsPluginSuite) configureRequest(config string) *plugin.ConfigureRequest {
	return &plugin.ConfigureRequest{
		Configuration: config,
	}
}

func (ps *KmsPluginSuite) defaultConfigureRequest() *plugin.ConfigureRequest {
	return &plugin.ConfigureRequest{
		Configuration: ps.defaultSerializedConfiguration(),
	}
}

func (ps *KmsPluginSuite) defaultSerializedConfiguration() string {
	config := ps.serializedConfiguration(validAccessKeyID, validSecretAccessKey, validRegion)
	return config
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

func (ps *KmsPluginSuite) verifyListKeys(withKeys bool, mockError error) {
	var keys []*kms.KeyListEntry

	if withKeys {
		keys = append(keys, &kms.KeyListEntry{
			KeyArn: aws.String("arn:aws:iam::123456789012:user/Development/key/1"),
			KeyId:  aws.String(awsKeyID),
		})
	}

	ps.kmsClientFake.expectedListKeysInput = &kms.ListKeysInput{}
	ps.kmsClientFake.listKeysErr = mockError

	ps.kmsClientFake.listKeysOutput = &kms.ListKeysOutput{
		Keys: keys,
	}
}

func (ps *KmsPluginSuite) verifyDescribeKey(keySpec string, mockError error) {
	km := &kms.KeyMetadata{
		KeyId:                 aws.String(awsKeyID),
		Description:           aws.String(keyPrefix + spireKeyID),
		CustomerMasterKeySpec: aws.String(keySpec),
		Enabled:               aws.Bool(true),
		CreationDate:          aws.Time(time.Now()),
	}

	ps.kmsClientFake.expectedDescribeKeyInput = &kms.DescribeKeyInput{KeyId: aws.String(awsKeyID)}
	ps.kmsClientFake.describeKeyErr = mockError

	ps.kmsClientFake.describeKeyOutput = &kms.DescribeKeyOutput{KeyMetadata: km}
}

func (ps *KmsPluginSuite) verifyGetPublicKey(mockError error) {
	var data string

	for n := 0; n < 4096; n++ {
		data = data + "*"
	}

	pub := &kms.GetPublicKeyOutput{
		CustomerMasterKeySpec: aws.String(kms.CustomerMasterKeySpecEccNistP256),
		KeyId:                 aws.String(awsKeyID),
		KeyUsage:              aws.String(signVerifyKeyUsage),
		PublicKey:             []byte(data),
		SigningAlgorithms:     []*string{aws.String(kms.SigningAlgorithmSpecRsassaPssSha256)},
	}

	ps.kmsClientFake.expectedGetPublicKeyInput = &kms.GetPublicKeyInput{KeyId: aws.String(awsKeyID)}
	ps.kmsClientFake.getPublicKeyErr = mockError

	ps.kmsClientFake.getPublicKeyOutput = pub
}

func (ps *KmsPluginSuite) verifyCreateKey(keySpec string, mockError error) {
	var desc = aws.String(keyPrefix + spireKeyID)
	var ku = aws.String(kms.KeyUsageTypeSignVerify)
	var ks = aws.String(keySpec)

	ps.kmsClientFake.expectedCreateKeyInput = &kms.CreateKeyInput{
		Description:           desc,
		KeyUsage:              ku,
		CustomerMasterKeySpec: ks,
	}

	ps.kmsClientFake.createKeyErr = mockError

	km := &kms.KeyMetadata{
		KeyId:                 aws.String(awsKeyID),
		CreationDate:          aws.Time(time.Now()),
		Description:           desc,
		KeyUsage:              ku,
		CustomerMasterKeySpec: ks,
	}
	ps.kmsClientFake.createKeyOutput = &kms.CreateKeyOutput{KeyMetadata: km}
}

func (ps *KmsPluginSuite) verifyScheduleKeyDeletion(mockError error) {
	ps.kmsClientFake.expectedScheduleKeyDeletionInput = &kms.ScheduleKeyDeletionInput{
		KeyId: aws.String(awsKeyID),
	}

	ps.kmsClientFake.scheduleKeyDeletionErr = mockError

	ps.kmsClientFake.scheduleKeyDeletionOutput = &kms.ScheduleKeyDeletionOutput{
		KeyId:        aws.String(awsKeyID),
		DeletionDate: aws.Time(time.Now()),
	}
}

func (ps *KmsPluginSuite) verifySignData(mockError error) {
	ps.kmsClientFake.expectedSignInput = &kms.SignInput{
		KeyId:            aws.String(awsKeyID),
		Message:          []byte("data"),
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: aws.String(kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256),
	}

	ps.kmsClientFake.signErr = mockError

	ps.kmsClientFake.signOutput = &kms.SignOutput{
		Signature: []byte("signature"),
	}
}
