package kms

import (
	"context"
	"errors"
	"fmt"
	"testing"

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
	plugin := New()

	plugin.SetLogger(hclog.Default())
	plugin.kmsClient = ps.kmsClientFake
	ps.rawPlugin = plugin
	ps.plugin = plugin
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
	ps.verifyListKeys(errors.New("List Keys error"))

	_, err := ps.plugin.Configure(ctx, ps.defaultConfigureRequest())
	ps.Require().Error(err)
}

// helper methods

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
	fmt.Println("Config: ", config)
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

func (ps *KmsPluginSuite) verifyListKeys(mockError error) {
	ps.kmsClientFake.expectedListKeysInput = &kms.ListKeysInput{}
	ps.kmsClientFake.err = mockError

	var keys []*kms.KeyListEntry

	ps.kmsClientFake.listKeysOutput = &kms.ListKeysOutput{
		Keys: keys,
	}
}
