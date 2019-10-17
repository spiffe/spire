package awssecret

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/upstreamca"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
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

	clock         *clock.Mock
	client        secretsManagerClient
	awsUpstreamCA upstreamca.Plugin
}

func (as *AWSSecretSuite) SetupTest() {
	as.clock = clock.NewMock(as.T())
	as.awsUpstreamCA = as.newAWSUpstreamCA("")
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
	validSpiffeID := "spiffe://localhost"
	csr, pubKey, err := util.NewCSRTemplate(validSpiffeID)
	as.Require().NoError(err)

	resp, err := as.awsUpstreamCA.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: csr})
	as.Require().NoError(err)
	as.Require().NotNil(resp)

	cert, err := x509.ParseCertificate(resp.SignedCertificate.CertChain)
	as.Require().NoError(err)

	isEqual, err := cryptoutil.PublicKeyEqual(cert.PublicKey, pubKey)
	as.Require().NoError(err)
	as.Require().True(isEqual)
}

func (as *AWSSecretSuite) Test_SubmitInvalidCSR() {
	invalidSpiffeIDs := []string{"invalid://localhost", "spiffe://not-trusted"}
	for _, invalidSpiffeID := range invalidSpiffeIDs {
		csr, _, err := util.NewCSRTemplate(invalidSpiffeID)
		as.Require().NoError(err)

		resp, err := as.awsUpstreamCA.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: csr})
		as.Require().Error(err)
		as.Require().Nil(resp)
	}

	invalidSequenceOfBytesAsCSR := []byte("invalid-csr")
	resp, err := as.awsUpstreamCA.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: invalidSequenceOfBytesAsCSR})
	as.Require().Error(err)
	as.Require().Nil(resp)
}

func (as *AWSSecretSuite) TestDeprecatedTTLUsedIfSet() {
	awsUpstreamCA := as.newAWSUpstreamCA("10h")

	// Submit CSR with 1 hour preferred TTL. The deprecated TTL configurable
	// (10 hours) should take precedence.
	as.testCSRTTL(awsUpstreamCA, 3600, time.Hour*10)
}

func (as *AWSSecretSuite) TestDeprecatedTTLUsesPreferredIfNoDeprecatedTTLSet() {
	awsUpstreamCA := as.newAWSUpstreamCA("")

	// If the preferred TTL is set, it should be used.
	as.testCSRTTL(awsUpstreamCA, 3600, time.Hour)

	// If the preferred TTL is zero, the default should be used.
	as.testCSRTTL(awsUpstreamCA, 0, x509svid.DefaultUpstreamCATTL)
}

func (as *AWSSecretSuite) testCSRTTL(plugin upstreamca.Plugin, preferredTTL int32, expectedTTL time.Duration) {
	validSpiffeID := "spiffe://localhost"
	csr, _, err := util.NewCSRTemplate(validSpiffeID)
	as.Require().NoError(err)

	resp, err := plugin.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: csr, PreferredTtl: preferredTTL})
	as.Require().NoError(err)
	as.Require().NotNil(resp)
	as.Require().NotNil(resp.SignedCertificate)

	certs, err := x509.ParseCertificates(resp.SignedCertificate.CertChain)
	as.Require().NoError(err)
	as.Require().Len(certs, 1)
	as.Require().Equal(as.clock.Now().Add(expectedTTL).UTC(), certs[0].NotAfter)
}

func (as *AWSSecretSuite) TestFailConfiguration() {
	config := AWSSecretConfiguration{
		KeyFileARN:      "",
		CertFileARN:     "",
		DeprecatedTTL:   "1h",
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

	var plugin upstreamca.Plugin
	as.LoadPlugin(builtin(m), &plugin)
	_, err := plugin.Configure(ctx, pluginConfig)
	as.Require().Error(err)
}

func (as *AWSSecretSuite) TestAWSSecret_GetPluginInfo() {
	res, err := as.awsUpstreamCA.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	as.Require().NoError(err)
	as.Require().NotNil(res)
}

func (as *AWSSecretSuite) newAWSUpstreamCA(deprecatedTTL string) upstreamca.Plugin {
	config := AWSSecretConfiguration{
		KeyFileARN:      "key",
		CertFileARN:     "cert",
		DeprecatedTTL:   deprecatedTTL,
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
	m.hooks.clock = as.clock

	var plugin upstreamca.Plugin
	as.LoadPlugin(builtin(m), &plugin)
	_, err = plugin.Configure(ctx, pluginConfig)
	as.Require().NoError(err)

	return plugin
}
