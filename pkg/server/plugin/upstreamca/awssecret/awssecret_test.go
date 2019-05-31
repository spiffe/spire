package awssecret

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/upstreamca"
	"github.com/spiffe/spire/test/spiretest"
)

var (
	ctx = context.Background()
)

const (
	config = `{
	"ttl":"1h",
	"key_file_arn":"key",
	"cert_file_arn":"cert",
	"assume_role_arn":"role",
	"access_key_id":"keyid",
	"region":"us-west-2",
	"secret_access_key":"accesskey"

}`
	trustDomain = "example.com"
)

func TestAWSSecret(t *testing.T) {
	spiretest.Run(t, new(AWSSecretSuite))
}

type AWSSecretSuite struct {
	spiretest.Suite

	client        secretsManagerClient
	awsUpstreamCA upstreamca.Plugin
}

func (s *AWSSecretSuite) SetupTest() {
	s.awsUpstreamCA = s.newAWSUpstreamCA()
}

func (as *AWSSecretSuite) TestConfigureNoGlobal() {
	a := newPlugin(newFakeSecretsManagerClient)
	req := new(spi.ConfigureRequest)
	resp, err := a.Configure(nil, req)
	as.Require().Error(err)
	as.Require().Nil(resp)
}

func (as *AWSSecretSuite) TestGetSecret() {
	svaluereq := secretsmanager.GetSecretValueInput{}
	secretid := aws.String("cert")
	svaluereq.SecretId = secretid
	resp, err := as.client.GetSecretValueWithContext(ctx, &svaluereq)

	as.Require().NotNil(resp)
	as.Require().NoError(err)
	as.Require().NotNil(aws.StringValue(resp.SecretString))
	as.Require().True(strings.HasPrefix(aws.StringValue(resp.SecretString), "-----BEGIN CERTIFICATE-----"))
	as.Require().NotNil(resp.ARN)
}

func (as *AWSSecretSuite) TestGetSecretFail() {
	svaluereq := secretsmanager.GetSecretValueInput{}
	secretid := aws.String("failure")
	svaluereq.SecretId = secretid
	resp, err := as.client.GetSecretValueWithContext(ctx, &svaluereq)

	as.Require().Error(err)
	as.Require().Nil(resp)
}

func (as *AWSSecretSuite) Test_SubmitValidCSR() {
	const testDataDir = "_test_data/csr_valid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	as.Require().NoError(err)

	for _, validCsrFile := range validCsrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		as.Require().NoError(err)
		block, rest := pem.Decode(csrPEM)
		as.Require().Len(rest, 0)

		resp, err := as.awsUpstreamCA.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		as.Require().NoError(err)
		as.Require().NotNil(resp)
	}
}

func (as *AWSSecretSuite) Test_SubmitInvalidCSR() {
	const testDataDir = "_test_data/csr_invalid"
	validCsrFiles, err := ioutil.ReadDir(testDataDir)
	as.Require().NoError(err)

	for _, validCsrFile := range validCsrFiles {
		csrPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCsrFile.Name()))
		as.Require().NoError(err)
		block, rest := pem.Decode(csrPEM)
		as.Require().Len(rest, 0)

		resp, err := as.awsUpstreamCA.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: block.Bytes})
		as.Require().Error(err)
		as.Require().Nil(resp)
	}
}

func (as *AWSSecretSuite) TestFailConfiguration() {
	config := AWSSecretConfiguration{
		KeyFileARN:      "",
		CertFileARN:     "",
		TTL:             "1h",
		AccessKeyID:     "keyid",
		Region:          "us-west-2",
		SecretAccessKey: "accesskey",
	}

	jsonConfig, _ := json.Marshal(config)
	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	}

	m := newPlugin(newFakeSecretsManagerClient)
	_, err := m.Configure(ctx, pluginConfig)
	as.Require().Error(err)
}

func (as *AWSSecretSuite) TestAWSSecret_GetPluginInfo() {
	res, err := as.awsUpstreamCA.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	as.Require().NoError(err)
	as.Require().NotNil(res)
}

func (as *AWSSecretSuite) newAWSUpstreamCA() upstreamca.Plugin {
	config := AWSSecretConfiguration{
		KeyFileARN:      "key",
		CertFileARN:     "cert",
		TTL:             "1h",
		AccessKeyID:     "keyid",
		SecretAccessKey: "accesskey",
	}

	jsonConfig, err := json.Marshal(config)
	as.Require().NoError(err)
	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
		GlobalConfig:  &spi.ConfigureRequest_GlobalConfig{TrustDomain: "localhost"},
	}

	as.client, err = newFakeSecretsManagerClient(nil, "region")
	as.Require().NoError(err)

	m := newPlugin(newFakeSecretsManagerClient)
	_, err = m.Configure(ctx, pluginConfig)
	as.Require().NoError(err)

	var plugin upstreamca.Plugin
	as.LoadPlugin(builtin(m), &plugin)
	return plugin
}
