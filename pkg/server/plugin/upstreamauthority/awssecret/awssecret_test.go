package awssecret

import (
	"context"
	"crypto/x509"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	upstreamauthorityv0 "github.com/spiffe/spire/proto/spire/plugin/server/upstreamauthority/v0"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"google.golang.org/grpc/codes"
)

var (
	ctx = context.Background()
)

func TestPlugin(t *testing.T) {
	spiretest.Run(t, new(Suite))
}

type Suite struct {
	spiretest.Suite

	clock  *clock.Mock
	client secretsManagerClient
	plugin upstreamauthorityv0.UpstreamAuthorityClient
}

func (as *Suite) SetupTest() {
	as.clock = clock.NewMock(as.T())
	as.plugin = as.newAWSUpstreamAuthority()
}

func (as *Suite) TestConfigureNoGlobal() {
	a := newPlugin(newFakeSecretsManagerClient)
	req := new(spi.ConfigureRequest)
	resp, err := a.Configure(context.Background(), req)
	as.Require().Error(err)
	as.Require().Nil(resp)
}

func (as *Suite) TestGetSecret() {
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

func (as *Suite) TestGetSecretFail() {
	svaluereq := secretsmanager.GetSecretValueInput{}
	secretid := aws.String("failure")
	svaluereq.SecretId = secretid
	resp, err := as.client.GetSecretValueWithContext(ctx, &svaluereq)

	as.Require().Error(err)
	as.Require().Nil(resp)
}

func (as *Suite) Test_MintX509CAValidCSR() {
	validSpiffeID := "spiffe://localhost"
	csr, pubKey, err := util.NewCSRTemplate(validSpiffeID)
	as.Require().NoError(err)

	resp, err := as.mintX509CA(as.plugin, &upstreamauthorityv0.MintX509CARequest{Csr: csr})
	as.Require().NoError(err)
	as.Require().NotNil(resp)

	as.Require().Len(resp.X509CaChain, 1)
	cert, err := x509.ParseCertificate(resp.X509CaChain[0])
	as.Require().NoError(err)

	isEqual, err := cryptoutil.PublicKeyEqual(cert.PublicKey, pubKey)
	as.Require().NoError(err)
	as.Require().True(isEqual)
}

func (as *Suite) TestMintX509CAInvalidCSR() {
	invalidSpiffeIDs := []string{"invalid://localhost", "spiffe://not-trusted"}
	for _, invalidSpiffeID := range invalidSpiffeIDs {
		csr, _, err := util.NewCSRTemplate(invalidSpiffeID)
		as.Require().NoError(err)

		resp, err := as.mintX509CA(as.plugin, &upstreamauthorityv0.MintX509CARequest{Csr: csr})
		as.Require().Error(err)
		as.Require().Nil(resp)
	}

	invalidSequenceOfBytesAsCSR := []byte("invalid-csr")
	resp, err := as.mintX509CA(as.plugin, &upstreamauthorityv0.MintX509CARequest{Csr: invalidSequenceOfBytesAsCSR})
	as.Require().Error(err)
	as.Require().Nil(resp)
}

func (as *Suite) TestMintX509CAUsesPreferredTTLIfSet() {
	awsUpstreamAuthority := as.newAWSUpstreamAuthority()

	// If the preferred TTL is set, it should be used.
	as.testCSRTTL(awsUpstreamAuthority, 3600, time.Hour)

	// If the preferred TTL is zero, the default should be used.
	as.testCSRTTL(awsUpstreamAuthority, 0, x509svid.DefaultUpstreamCATTL)
}

func (as *Suite) testCSRTTL(plugin upstreamauthorityv0.UpstreamAuthorityClient, preferredTTL int32, expectedTTL time.Duration) {
	validSpiffeID := "spiffe://localhost"
	csr, _, err := util.NewCSRTemplate(validSpiffeID)
	as.Require().NoError(err)

	resp, err := as.mintX509CA(plugin, &upstreamauthorityv0.MintX509CARequest{Csr: csr, PreferredTtl: preferredTTL})
	as.Require().NoError(err)
	as.Require().NotNil(resp)

	as.Require().Len(resp.X509CaChain, 1)
	certs, err := x509.ParseCertificates(resp.X509CaChain[0])
	as.Require().NoError(err)
	as.Require().Len(certs, 1)
	as.Require().Equal(as.clock.Now().Add(expectedTTL).UTC(), certs[0].NotAfter)
}

func (as *Suite) TestFailConfiguration() {
	config := Config{
		KeyFileARN:      "",
		CertFileARN:     "",
		AccessKeyID:     "keyid",
		Region:          "us-west-2",
		SecretAccessKey: "accesskey",
	}

	m := newPlugin(newFakeSecretsManagerClient)

	var err error
	plugintest.Load(as.T(), builtin(m), new(upstreamauthority.V0),
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("localhost"),
		}),
		plugintest.ConfigureJSON(config),
		plugintest.CaptureConfigureError(&err))
	as.Require().Error(err)
}

func (as *Suite) TestAWSSecret_GetPluginInfo() {
	res, err := as.plugin.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	as.Require().NoError(err)
	as.Require().NotNil(res)
}

func (as *Suite) newAWSUpstreamAuthority() upstreamauthorityv0.UpstreamAuthorityClient {
	config := Config{
		KeyFileARN:      "key",
		CertFileARN:     "cert",
		AccessKeyID:     "keyid",
		SecretAccessKey: "accesskey",
	}

	var err error
	as.client, err = newFakeSecretsManagerClient(nil, "region")
	as.Require().NoError(err)

	m := newPlugin(newFakeSecretsManagerClient)
	m.hooks.clock = as.clock

	v0 := new(upstreamauthority.V0)
	plugintest.Load(as.T(), builtin(m), v0,
		plugintest.CoreConfig(catalog.CoreConfig{
			TrustDomain: spiffeid.RequireTrustDomainFromString("localhost"),
		}),
		plugintest.ConfigureJSON(config),
	)
	return v0.UpstreamAuthorityClient
}

func (as *Suite) TestPublishJWTKey() {
	stream, err := as.plugin.PublishJWTKey(ctx, &upstreamauthorityv0.PublishJWTKeyRequest{})
	as.Require().Nil(err)
	as.Require().NotNil(stream)

	resp, err := stream.Recv()
	as.Require().Nil(resp, "no response expected")
	as.RequireGRPCStatus(err, codes.Unimplemented, "aws-secret: publishing upstream is unsupported")
}

func (as *Suite) mintX509CA(plugin upstreamauthorityv0.UpstreamAuthorityClient, req *upstreamauthorityv0.MintX509CARequest) (*upstreamauthorityv0.MintX509CAResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stream, err := plugin.MintX509CA(ctx, req)
	as.Require().NoError(err)
	as.Require().NotNil(stream)

	// Get response and error to be returned
	response, err := stream.Recv()
	if err == nil {
		// Verify stream is closed
		_, eofErr := stream.Recv()
		as.Require().Equal(io.EOF, eofErr)
	}

	return response, err
}
