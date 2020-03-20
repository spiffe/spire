package awspca

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/acmpca"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/util"
	"google.golang.org/grpc/codes"
)

const (
	// Defaults used for testing
	validTrustDomain             = "example.com"
	validRegion                  = "us-west-2"
	validCertificateAuthorityARN = "arn:aws:acm-pca:us-west-2:123456789012:certificate-authority/abcd-1234"
	validCASigningTemplateARN    = "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
	validSigningAlgorithm        = "SHA256WITHRSA"
	validAssumeRoleARN           = "arn:aws:iam::123456789012:role/spire-server-role"
	// The header and footer type for a PEM-encoded certificate
	certificateType = "CERTIFICATE"

	testTTL = 300
)

var (
	ctx = context.Background()
)

func TestPCAPlugin(t *testing.T) {
	spiretest.Run(t, new(PCAPluginSuite))
}

type PCAPluginSuite struct {
	spiretest.Suite

	// Mocks used for testing the plugin
	clock *clock.Mock

	pcaClientFake *pcaClientFake
	rawPlugin     *PCAPlugin
	// The plugin under test
	plugin upstreamauthority.Plugin
}

func (as *PCAPluginSuite) SetupTest() {
	// Setup mocks
	as.clock = clock.NewMock(as.T())

	as.pcaClientFake = &pcaClientFake{}

	// Setup plugin
	plugin := newPlugin(func(config *PCAPluginConfiguration) (PCAClient, error) {
		return as.pcaClientFake, nil
	})
	plugin.hooks.clock = as.clock
	plugin.SetLogger(hclog.Default())
	as.rawPlugin = plugin
	as.LoadPlugin(builtin(plugin), &as.plugin)
}

func (as *PCAPluginSuite) Test_GetPluginInfo() {
	response, err := as.plugin.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	as.Require().NoError(err)
	as.Require().NotNil(response)
}

func (as *PCAPluginSuite) Test_Configure() {
	as.pcaClientFake.recycle(as.T())

	as.verifyDescribeCertificateAuthority("ACTIVE", nil)

	_, err := as.rawPlugin.Configure(ctx, as.defaultConfigureRequest())
	as.Require().NoError(err)
}

func (as *PCAPluginSuite) Test_Configure_Default_SigningAlgorithm() {
	as.pcaClientFake.recycle(as.T())

	as.verifyDescribeCertificateAuthority("ACTIVE", nil)

	// If the configuration does not contain a signing algorithm, we'll fall
	// back to the CA's pre-configured value
	_, err := as.rawPlugin.Configure(ctx, as.optionalConfigureRequest("", validCASigningTemplateARN))
	as.Require().NoError(err)
	as.Require().Equal("defaultSigningAlgorithm", as.rawPlugin.signingAlgorithm)
}

func (as *PCAPluginSuite) Test_Configure_Default_CASigningTemplateARN() {
	as.pcaClientFake.recycle(as.T())

	as.verifyDescribeCertificateAuthority("ACTIVE", nil)

	// If the configuration does not contain a CA signing template ARN, we'll fall
	// back to the default value.
	_, err := as.rawPlugin.Configure(ctx, as.optionalConfigureRequest(validSigningAlgorithm, ""))
	as.Require().NoError(err)
	as.Require().Equal(defaultCASigningTemplateArn, as.rawPlugin.caSigningTemplateArn)
}

func (as *PCAPluginSuite) Test_Configure_Disabled_CA() {
	as.pcaClientFake.recycle(as.T())

	// The certificate authority is in a DISABLED state
	as.verifyDescribeCertificateAuthority("DISABLED", nil)

	_, err := as.rawPlugin.Configure(ctx, as.defaultConfigureRequest())

	// The configuration should proceed without error, as we
	// will attempt to issue against it, allowing the server to stay alive
	// and recover gracefully.
	as.Require().NoError(err)
}

func (as *PCAPluginSuite) Test_Configure_DescribeCertificateAuthorityError() {
	as.pcaClientFake.recycle(as.T())

	as.verifyDescribeCertificateAuthority("", errors.New("describe error"))

	_, err := as.rawPlugin.Configure(ctx, as.defaultConfigureRequest())
	as.Require().Error(err)
}

func (as *PCAPluginSuite) Test_Configure_Invalid() {
	// Missing region
	invalidConfig := `{
		"certificate_authority_arn":"caArn",
		"ca_signing_template_arn":"templateArn",
		"signing_algorithm":"signingAlgorithm"
	}`
	_, err := as.rawPlugin.Configure(ctx, as.configureRequest(validTrustDomain, invalidConfig))
	as.Require().Error(err)

	// Missing certificate authority ARN
	invalidConfig = `{
		"region":"us-west-2",
		"ca_signing_template_arn":"templateArn",
		"signing_algorithm":"signingAlgorithm"
	}`
	_, err = as.rawPlugin.Configure(ctx, as.configureRequest(validTrustDomain, invalidConfig))
	as.Require().Error(err)
}

func (as *PCAPluginSuite) Test_Configure_DecodeError() {
	malformedConfig := `{
		badjson
	}`
	_, err := as.rawPlugin.Configure(ctx, as.configureRequest(validTrustDomain, malformedConfig))
	as.Require().Error(err)
}

func (as *PCAPluginSuite) Test_MintX509CA() {
	as.pcaClientFake.recycle(as.T())
	as.configurePlugin()

	// Since ACM does the signing, these are used to verify the signed
	// bytes returned by the GetCertificate API are as expected.
	expectedRoot, encodedRoot := as.certificateAuthorityFixture()
	expectedIntermediate, encodedIntermediate := as.certificateAuthorityFixture()
	expectedCert, encodedCert := as.SVIDFixture()

	// Should send an issue request
	csr, expectedEncodedCsr := as.generateCSR()
	as.verifyIssueCertificate(expectedEncodedCsr, nil)

	// Should wait for the certificate to reach the issued state
	as.verifyWaitUntilCertificateIssued(nil)

	// Should get the contents of the certificate once issued
	encodedCertChain := new(bytes.Buffer)
	_, err := encodedCertChain.Write(encodedIntermediate.Bytes())
	as.Require().NoError(err)
	_, err = encodedCertChain.Write(encodedRoot.Bytes())
	as.Require().NoError(err)
	as.verifyGetCertificate(encodedCert, encodedCertChain, nil)

	stream, err := as.plugin.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{
		Csr:          csr,
		PreferredTtl: testTTL,
	})
	as.Require().NoError(err)
	as.Require().NotNil(stream)

	// The resulting response should not error, and should contain the expected
	// values from ACM.
	response, err := stream.Recv()
	as.Require().NoError(err)
	as.Require().NotNil(response)
	as.Require().Equal([][]byte{expectedCert.Raw, expectedIntermediate.Raw}, response.X509CaChain)
	as.Require().Equal([][]byte{expectedRoot.Raw}, response.UpstreamX509Roots)
}

func (as *PCAPluginSuite) Test_MintX509CA_IssuanceError() {
	as.pcaClientFake.recycle(as.T())
	as.configurePlugin()

	// Issuance returns an error
	csr, expectedEncodedCsr := as.generateCSR()
	as.verifyIssueCertificate(expectedEncodedCsr, errors.New("issuance error"))

	// The resulting response should return an error
	stream, err := as.plugin.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{
		Csr:          csr,
		PreferredTtl: testTTL,
	})
	as.Require().NoError(err)
	as.Require().NotNil(stream)

	response, err := stream.Recv()
	as.Require().Nil(response)
	as.Require().Error(err)
}

func (as *PCAPluginSuite) Test_MintX509CA_IssuanceWaitError() {
	as.pcaClientFake.recycle(as.T())
	as.configurePlugin()

	// Should send an issue request
	csr, expectedEncodedCsr := as.generateCSR()
	as.verifyIssueCertificate(expectedEncodedCsr, nil)

	// But the wait call returns an error
	as.verifyWaitUntilCertificateIssued(errors.New("issuance waiting error"))

	stream, err := as.plugin.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{
		Csr:          csr,
		PreferredTtl: testTTL,
	})
	as.Require().NoError(err)
	as.Require().NotNil(stream)

	// The resulting response should error
	response, err := stream.Recv()
	as.Require().Nil(response)
	as.Require().Error(err)
}

func (as *PCAPluginSuite) Test_MintX509CA_GetCertificateError() {
	as.pcaClientFake.recycle(as.T())
	as.configurePlugin()

	csr, expectedEncodedCsr := as.generateCSR()

	// Should send an issue request
	as.verifyIssueCertificate(expectedEncodedCsr, nil)

	// Should wait for the certificate to reach the issued state
	as.verifyWaitUntilCertificateIssued(nil)

	// But the GetCertificate call returns an error
	as.verifyGetCertificate(nil, nil, errors.New("get certificate error"))

	stream, err := as.plugin.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{
		Csr:          csr,
		PreferredTtl: testTTL,
	})
	as.Require().NoError(err)
	as.Require().NotNil(stream)

	// The resulting response should error
	response, err := stream.Recv()
	as.Require().Nil(response)
	as.Require().Error(err)
}

func (as *PCAPluginSuite) Test_MintX509CA_GetCertificate_CertificateParseError() {
	as.pcaClientFake.recycle(as.T())
	as.configurePlugin()

	csr, expectedEncodedCsr := as.generateCSR()

	// Should send an issue request
	as.verifyIssueCertificate(expectedEncodedCsr, nil)

	// Should wait for the certificate to reach the issued state
	as.verifyWaitUntilCertificateIssued(nil)

	// But the GetCertificate call returns no certificate
	_, encodedBundle := as.certificateAuthorityFixture()
	as.verifyGetCertificate(nil, encodedBundle, nil)

	stream, err := as.plugin.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{
		Csr:          csr,
		PreferredTtl: testTTL,
	})
	as.Require().NoError(err)
	as.Require().NotNil(stream)

	// The resulting response should error
	response, err := stream.Recv()
	as.Require().Nil(response)
	as.Require().Error(err)
}

func (as *PCAPluginSuite) Test_MintX509CA_GetCertificate_CertificateChainParseError() {
	as.pcaClientFake.recycle(as.T())
	as.configurePlugin()

	csr, expectedEncodedCsr := as.generateCSR()

	// Should send an issue request
	as.verifyIssueCertificate(expectedEncodedCsr, nil)

	// Should wait for the certificate to reach the issued state
	as.verifyWaitUntilCertificateIssued(nil)

	// But the GetCertificate call returns no bundle
	_, encodedCert := as.SVIDFixture()
	as.verifyGetCertificate(encodedCert, nil, nil)

	stream, err := as.plugin.MintX509CA(ctx, &upstreamauthority.MintX509CARequest{
		Csr:          csr,
		PreferredTtl: testTTL,
	})
	as.Require().NoError(err)
	as.Require().NotNil(stream)

	// The resulting response should error
	response, err := stream.Recv()
	as.Require().Nil(response)
	as.Require().Error(err)
}

func (as *PCAPluginSuite) verifyDescribeCertificateAuthority(status string, mockError error) {
	as.pcaClientFake.expectedDescribeInput = &acmpca.DescribeCertificateAuthorityInput{
		CertificateAuthorityArn: aws.String(validCertificateAuthorityARN),
	}
	as.pcaClientFake.err = mockError

	as.pcaClientFake.describeCertificateOutput = &acmpca.DescribeCertificateAuthorityOutput{
		CertificateAuthority: &acmpca.CertificateAuthority{
			CertificateAuthorityConfiguration: &acmpca.CertificateAuthorityConfiguration{
				SigningAlgorithm: aws.String("defaultSigningAlgorithm"),
			},
			// For all possible statuses, see:
			// https://docs.aws.amazon.com/cli/latest/reference/acm-pca/describe-certificate-authority.html
			Status: aws.String(status),
		},
	}
}

func (as *PCAPluginSuite) verifyIssueCertificate(csr *bytes.Buffer, mockError error) {
	as.pcaClientFake.expectedIssueInput = &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(validCertificateAuthorityARN),
		SigningAlgorithm:        aws.String(validSigningAlgorithm),
		Csr:                     csr.Bytes(),
		TemplateArn:             aws.String(validCASigningTemplateARN),
		Validity: &acmpca.Validity{
			Type:  aws.String(acmpca.ValidityPeriodTypeAbsolute),
			Value: aws.Int64(as.clock.Now().Add(time.Second * testTTL).Unix()),
		},
	}
	as.pcaClientFake.err = mockError
	as.pcaClientFake.issueCertificateOutput = &acmpca.IssueCertificateOutput{
		CertificateArn: aws.String("certificateArn"),
	}
}

func (as *PCAPluginSuite) verifyWaitUntilCertificateIssued(mockError error) {
	as.pcaClientFake.expectedGetCertificateInput = &acmpca.GetCertificateInput{
		CertificateAuthorityArn: aws.String(validCertificateAuthorityARN),
		CertificateArn:          aws.String("certificateArn"),
	}

	as.pcaClientFake.err = mockError
}

func (as *PCAPluginSuite) verifyGetCertificate(encodedCert *bytes.Buffer, encodedCertChain *bytes.Buffer, mockError error) {
	as.pcaClientFake.expectedGetCertificateInput = &acmpca.GetCertificateInput{
		CertificateAuthorityArn: aws.String(validCertificateAuthorityARN),
		CertificateArn:          aws.String("certificateArn"),
	}
	as.pcaClientFake.err = mockError
	as.pcaClientFake.getCertificateOutput = &acmpca.GetCertificateOutput{
		Certificate:      aws.String(encodedCert.String()),
		CertificateChain: aws.String(encodedCertChain.String()),
	}
}

func (as *PCAPluginSuite) configurePlugin() {
	as.verifyDescribeCertificateAuthority("ACTIVE", nil)

	_, err := as.rawPlugin.Configure(ctx, as.defaultConfigureRequest())
	as.Require().NoError(err)
}

func (as *PCAPluginSuite) defaultSerializedConfiguration() string {
	config := as.serializedConfiguration(validRegion, validCertificateAuthorityARN, validCASigningTemplateARN, validSigningAlgorithm, validAssumeRoleARN)
	fmt.Println("Config: ", config)
	return config
}

func (as *PCAPluginSuite) serializedConfiguration(region, certificateAuthorityARN, caSigningTemplateARN, signingAlgorithm, assumeRoleARN string) string {
	return fmt.Sprintf(`{
		"region": "%s",
		"certificate_authority_arn": "%s",
		"ca_signing_template_arn":"%s",
		"signing_algorithm":"%s",
		"assume_role_arn":"%s"
		}`,
		region,
		certificateAuthorityARN,
		caSigningTemplateARN,
		signingAlgorithm,
		assumeRoleARN)
}

func (as *PCAPluginSuite) defaultConfigureRequest() *spi.ConfigureRequest {
	return &spi.ConfigureRequest{
		Configuration: as.defaultSerializedConfiguration(),
		GlobalConfig: &spi.ConfigureRequest_GlobalConfig{
			TrustDomain: validTrustDomain,
		},
	}
}

func (as *PCAPluginSuite) optionalConfigureRequest(signingAlgorithm, caSigningTemplateARN string) *spi.ConfigureRequest {
	return &spi.ConfigureRequest{
		Configuration: as.serializedConfiguration(validRegion, validCertificateAuthorityARN, caSigningTemplateARN, signingAlgorithm, validAssumeRoleARN),
		GlobalConfig: &spi.ConfigureRequest_GlobalConfig{
			TrustDomain: validTrustDomain,
		},
	}
}

func (as *PCAPluginSuite) configureRequest(trustDomain, config string) *spi.ConfigureRequest {
	return &spi.ConfigureRequest{
		Configuration: config,
		GlobalConfig: &spi.ConfigureRequest_GlobalConfig{
			TrustDomain: trustDomain,
		},
	}
}

func (as *PCAPluginSuite) certificateAuthorityFixture() (*x509.Certificate, *bytes.Buffer) {
	ca, _, err := util.LoadCAFixture()
	as.Require().NoError(err)
	encodedCA := new(bytes.Buffer)
	err = pem.Encode(encodedCA, &pem.Block{
		Type:  certificateType,
		Bytes: ca.Raw,
	})
	as.Require().NoError(err)
	return ca, encodedCA
}

func (as *PCAPluginSuite) SVIDFixture() (*x509.Certificate, *bytes.Buffer) {
	cert, _, err := util.LoadSVIDFixture()
	as.Require().NoError(err)
	encodedCert := new(bytes.Buffer)
	err = pem.Encode(encodedCert, &pem.Block{
		Type:  certificateType,
		Bytes: cert.Raw,
	})
	as.Require().NoError(err)
	return cert, encodedCert
}

func (as *PCAPluginSuite) generateCSR() ([]byte, *bytes.Buffer) {
	csr, _, err := util.NewCSRTemplate("spiffe://example.com/foo")
	as.Require().NoError(err)
	encodedCsr := new(bytes.Buffer)
	err = pem.Encode(encodedCsr, &pem.Block{
		Type:  csrRequestType,
		Bytes: csr,
	})
	as.Require().NoError(err)
	return csr, encodedCsr
}

func (as *PCAPluginSuite) TestPublishJWTKey() {
	stream, err := as.plugin.PublishJWTKey(ctx, &upstreamauthority.PublishJWTKeyRequest{})
	as.Require().NoError(err)
	as.Require().NotNil(stream)

	resp, err := stream.Recv()
	as.Require().Nil(resp, "no response expected")
	as.RequireGRPCStatus(err, codes.Unimplemented, "aws-pca: publishing upstream is unsupported")
}
