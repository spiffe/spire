package awspca

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

const (
	// Defaults used for testing
	validRegion                  = "us-west-2"
	validCertificateAuthorityARN = "arn:aws:acm-pca:us-west-2:123456789012:certificate-authority/abcd-1234"
	validCASigningTemplateARN    = "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
	validSigningAlgorithm        = "SHA256WITHRSA"
	validAssumeRoleARN           = "arn:aws:iam::123456789012:role/spire-server-role"
	validSupplementalBundlePath  = ""
	// The header and footer type for a PEM-encoded certificate
	certificateType = "CERTIFICATE"

	testTTL = 300
)

func TestConfigure(t *testing.T) {
	for _, tt := range []struct {
		test                   string
		expectCode             codes.Code
		expectMsgPrefix        string
		overrideConfig         string
		newClientErr           error
		expectedDescribeStatus string
		expectDescribeErr      error
		expectConfig           *configuration

		// All allowed configurations
		region                  string
		endpoint                string
		certificateAuthorityARN string
		signingAlgorithm        string
		caSigningTemplateARN    string
		assumeRoleARN           string
		supplementalBundlePath  string
	}{
		{
			test:                    "success",
			expectedDescribeStatus:  "ACTIVE",
			region:                  validRegion,
			certificateAuthorityARN: validCertificateAuthorityARN,
			caSigningTemplateARN:    validCASigningTemplateARN,
			signingAlgorithm:        validSigningAlgorithm,
			assumeRoleARN:           validAssumeRoleARN,
			supplementalBundlePath:  validSupplementalBundlePath,
			expectConfig: &configuration{
				certificateAuthorityArn: "arn:aws:acm-pca:us-west-2:123456789012:certificate-authority/abcd-1234",
				signingAlgorithm:        "SHA256WITHRSA",
				caSigningTemplateArn:    "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1",
			},
		},
		{
			test:                    "using default signing algorithm",
			expectedDescribeStatus:  "ACTIVE",
			region:                  validRegion,
			certificateAuthorityARN: validCertificateAuthorityARN,
			caSigningTemplateARN:    validCASigningTemplateARN,
			assumeRoleARN:           validAssumeRoleARN,
			supplementalBundlePath:  validSupplementalBundlePath,
			expectConfig: &configuration{
				certificateAuthorityArn: "arn:aws:acm-pca:us-west-2:123456789012:certificate-authority/abcd-1234",
				signingAlgorithm:        "defaultSigningAlgorithm",
				caSigningTemplateArn:    "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1",
			},
		},
		{
			test:                    "using default signing template ARN",
			expectedDescribeStatus:  "ACTIVE",
			region:                  validRegion,
			certificateAuthorityARN: validCertificateAuthorityARN,
			signingAlgorithm:        validSigningAlgorithm,
			assumeRoleARN:           validAssumeRoleARN,
			supplementalBundlePath:  validSupplementalBundlePath,
			expectConfig: &configuration{
				certificateAuthorityArn: "arn:aws:acm-pca:us-west-2:123456789012:certificate-authority/abcd-1234",
				signingAlgorithm:        "SHA256WITHRSA",
				caSigningTemplateArn:    defaultCASigningTemplateArn,
			},
		},
		{
			test:                    "DISABLED template",
			expectedDescribeStatus:  "DISABLED",
			region:                  validRegion,
			certificateAuthorityARN: validCertificateAuthorityARN,
			caSigningTemplateARN:    validCASigningTemplateARN,
			signingAlgorithm:        validSigningAlgorithm,
			assumeRoleARN:           validAssumeRoleARN,
			supplementalBundlePath:  validSupplementalBundlePath,
			expectConfig: &configuration{
				certificateAuthorityArn: "arn:aws:acm-pca:us-west-2:123456789012:certificate-authority/abcd-1234",
				signingAlgorithm:        "SHA256WITHRSA",
				caSigningTemplateArn:    "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1",
			},
		},
		{
			test:                    "Describe certificate fails",
			expectDescribeErr:       awsErr("Internal", "some error", errors.New("oh no")),
			region:                  validRegion,
			certificateAuthorityARN: validCertificateAuthorityARN,
			caSigningTemplateARN:    validCASigningTemplateARN,
			signingAlgorithm:        validSigningAlgorithm,
			assumeRoleARN:           validAssumeRoleARN,
			supplementalBundlePath:  validSupplementalBundlePath,
			expectCode:              codes.Internal,
			expectMsgPrefix:         "failed to describe CertificateAuthority: Internal: some error\ncaused by: oh no",
		},
		{
			test:                    "Invalid supplemental bundle Path",
			expectedDescribeStatus:  "ACTIVE",
			region:                  validRegion,
			certificateAuthorityARN: validCertificateAuthorityARN,
			caSigningTemplateARN:    validCASigningTemplateARN,
			signingAlgorithm:        validSigningAlgorithm,
			assumeRoleARN:           validAssumeRoleARN,
			supplementalBundlePath:  "testdata/i_am_not_a_certificate.txt",
			expectCode:              codes.InvalidArgument,
			expectMsgPrefix:         "failed to load supplemental bundle: no PEM blocks",
		},
		{
			test:                    "Missing region",
			expectedDescribeStatus:  "ACTIVE",
			certificateAuthorityARN: validCertificateAuthorityARN,
			caSigningTemplateARN:    validCASigningTemplateARN,
			signingAlgorithm:        validSigningAlgorithm,
			assumeRoleARN:           validAssumeRoleARN,
			supplementalBundlePath:  validSupplementalBundlePath,
			expectCode:              codes.InvalidArgument,
			expectMsgPrefix:         "configuration is missing a region",
		},
		{
			test:                   "Missing certificate ARN",
			expectedDescribeStatus: "ACTIVE",
			region:                 validRegion,
			caSigningTemplateARN:   validCASigningTemplateARN,
			signingAlgorithm:       validSigningAlgorithm,
			assumeRoleARN:          validAssumeRoleARN,
			supplementalBundlePath: validSupplementalBundlePath,
			expectCode:             codes.InvalidArgument,
			expectMsgPrefix:        "configuration is missing a certificate authority ARN",
		},
		{
			test: "Malformed config",
			overrideConfig: `{
badjson
}`,
			expectCode:      codes.InvalidArgument,
			expectMsgPrefix: "unable to decode configuration:",
		},
		{
			test:                    "Fail to create client",
			newClientErr:            awsErr("MissingEndpoint", "'Endpoint' configuration is required for this service", nil),
			region:                  validRegion,
			certificateAuthorityARN: validCertificateAuthorityARN,
			caSigningTemplateARN:    validCASigningTemplateARN,
			signingAlgorithm:        validSigningAlgorithm,
			assumeRoleARN:           validAssumeRoleARN,
			supplementalBundlePath:  validSupplementalBundlePath,
			expectCode:              codes.Internal,
			expectMsgPrefix:         "failed to create client: MissingEndpoint: 'Endpoint' configuration is required for this service",
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			client := &pcaClientFake{t: t}
			clock := clock.NewMock()

			var err error

			options := []plugintest.Option{
				plugintest.CaptureConfigureError(&err),
			}

			if tt.overrideConfig != "" {
				options = append(options, plugintest.Configure(tt.overrideConfig))
			} else {
				options = append(options, plugintest.ConfigureJSON(Configuration{
					Region:                  tt.region,
					Endpoint:                tt.endpoint,
					CertificateAuthorityARN: tt.certificateAuthorityARN,
					SigningAlgorithm:        tt.signingAlgorithm,
					CASigningTemplateARN:    tt.caSigningTemplateARN,
					AssumeRoleARN:           tt.assumeRoleARN,
					SupplementalBundlePath:  tt.supplementalBundlePath,
				}))
			}

			p := new(PCAPlugin)
			p.hooks.clock = clock
			p.hooks.newClient = newACMPCAClientFunc(func(ctx context.Context, config *Configuration) (PCAClient, error) {
				if tt.newClientErr != nil {
					return nil, tt.newClientErr
				}
				return client, nil
			})
			setupWaitUntilCertificateIssued(t, p, nil)

			setupDescribeCertificateAuthority(client, tt.expectedDescribeStatus, tt.expectDescribeErr)

			plugintest.Load(t, builtin(p), nil, options...)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)

			require.Equal(t, tt.expectConfig, p.config)
		})
	}
}

func TestMintX509CA(t *testing.T) {
	bundleCert, encodedRoot := certificateAuthorityFixture(t)
	intermediateCert, encodedIntermediate := certificateAuthorityFixture(t)
	expectCert, encodedCert := svidFixture(t)

	// Should get the contents of the certificate once issued
	encodedCertChain := new(bytes.Buffer)
	_, err := encodedCertChain.Write(encodedIntermediate.Bytes())
	require.NoError(t, err)
	_, err = encodedCertChain.Write(encodedRoot.Bytes())
	require.NoError(t, err)

	makeCSR := func(spiffeID string) []byte {
		csr, _, err := util.NewCSRTemplate(spiffeID)
		require.NoError(t, err)

		return csr
	}

	endcodeCSR := func(csr []byte) *bytes.Buffer {
		encodedCsr := new(bytes.Buffer)
		err := pem.Encode(encodedCsr, &pem.Block{
			Type:  csrRequestType,
			Bytes: csr,
		})
		require.NoError(t, err)

		return encodedCsr
	}

	// Load and configure supplemental bundle
	// This fixture includes a copy of the upstream root to test deduplication
	supplementalBundlePath := "testdata/arbitrary_certificate_with_upstream_root.pem"
	supplementalCert, err := pemutil.LoadCertificates("testdata/arbitrary_certificate_with_upstream_root.pem")
	require.NoError(t, err)

	successConfig := &Configuration{
		Region:                  validRegion,
		CertificateAuthorityARN: validCertificateAuthorityARN,
		CASigningTemplateARN:    validCASigningTemplateARN,
		SigningAlgorithm:        validSigningAlgorithm,
		AssumeRoleARN:           validAssumeRoleARN,
		SupplementalBundlePath:  "",
	}

	for _, tt := range []struct {
		test   string
		config *Configuration

		client *pcaClientFake

		csr                     []byte
		preferredTTL            time.Duration
		issuedCertErr           error
		waitCertErr             error
		expectCode              codes.Code
		getCertificateCert      string
		getCertificateCertChain string
		getCertificateErr       error
		expectMsgPrefix         string
		expectX509CA            []*x509.Certificate
		expectX509Authorities   []*x509certificate.X509Authority
		expectTTL               time.Duration
	}{
		{
			test:         "Successful mint",
			config:       successConfig,
			csr:          makeCSR("spiffe://example.com/foo"),
			preferredTTL: 300 * time.Second,
			expectX509CA: []*x509.Certificate{expectCert, intermediateCert},
			expectX509Authorities: []*x509certificate.X509Authority{
				{
					Certificate: bundleCert,
				},
			},
			getCertificateCert:      encodedCert.String(),
			getCertificateCertChain: encodedCertChain.String(),
		},
		{
			test: "With supplemental bundle",
			config: &Configuration{
				Region:                  validRegion,
				CertificateAuthorityARN: validCertificateAuthorityARN,
				CASigningTemplateARN:    validCASigningTemplateARN,
				SigningAlgorithm:        validSigningAlgorithm,
				AssumeRoleARN:           validAssumeRoleARN,
				SupplementalBundlePath:  supplementalBundlePath,
			},
			csr:          makeCSR("spiffe://example.com/foo"),
			preferredTTL: 300 * time.Second,
			expectX509CA: []*x509.Certificate{expectCert, intermediateCert},
			expectX509Authorities: []*x509certificate.X509Authority{
				{
					Certificate: bundleCert,
				},
				{
					Certificate: supplementalCert[0],
				},
			},
			getCertificateCert:      encodedCert.String(),
			getCertificateCertChain: encodedCertChain.String(),
		},
		{
			test:            "Issuance fails",
			config:          successConfig,
			csr:             makeCSR("spiffe://example.com/foo"),
			preferredTTL:    300 * time.Second,
			issuedCertErr:   awsErr("Internal", "some error", errors.New("oh no")),
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(aws_pca): failed submitting CSR: Internal: some error\ncaused by: oh no",
		},
		{
			test:            "Issuance wait fails",
			config:          successConfig,
			csr:             makeCSR("spiffe://example.com/foo"),
			preferredTTL:    300 * time.Second,
			waitCertErr:     awsErr("Internal", "some error", errors.New("oh no")),
			expectCode:      codes.Internal,
			expectMsgPrefix: "upstreamauthority(aws_pca): failed waiting for issuance: Internal: some error\ncaused by: oh no",
		},
		{
			test:              "Get certificate fails",
			config:            successConfig,
			csr:               makeCSR("spiffe://example.com/foo"),
			preferredTTL:      300 * time.Second,
			getCertificateErr: awsErr("Internal", "some error", errors.New("oh no")),
			expectCode:        codes.Internal,
			expectMsgPrefix:   "upstreamauthority(aws_pca): failed to get certificates: Internal: some error\ncaused by: oh no",
		},
		{
			test:                    "Fails to parse certificate from GetCertificate",
			config:                  successConfig,
			csr:                     makeCSR("spiffe://example.com/foo"),
			preferredTTL:            300 * time.Second,
			getCertificateCert:      "no a certificate",
			getCertificateCertChain: encodedCertChain.String(),
			expectCode:              codes.Internal,
			expectMsgPrefix:         "upstreamauthority(aws_pca): failed to parse certificate from response: no PEM blocks",
		},
		{
			test:                    "Fails to parse certificate chain from GetCertificate",
			config:                  successConfig,
			csr:                     makeCSR("spiffe://example.com/foo"),
			preferredTTL:            300 * time.Second,
			getCertificateCert:      encodedCert.String(),
			getCertificateCertChain: "no a cert chain",
			expectCode:              codes.Internal,
			expectMsgPrefix:         "upstreamauthority(aws_pca): failed to parse certificate chain from response: no PEM blocks",
		},
	} {
		tt := tt
		t.Run(tt.test, func(t *testing.T) {
			client := &pcaClientFake{t: t}
			clk := clock.NewMock()

			// Configure plugin
			setupDescribeCertificateAuthority(client, "ACTIVE", nil)
			p := New()
			p.hooks.newClient = func(ctx context.Context, config *Configuration) (PCAClient, error) {
				return client, nil
			}
			p.hooks.clock = clk

			ua := new(upstreamauthority.V1)
			plugintest.Load(t, builtin(p), ua,
				plugintest.ConfigureJSON(tt.config),
			)

			var expectPem []byte
			if len(tt.csr) > 0 {
				expectPem = endcodeCSR(tt.csr).Bytes()
			}

			// Setup expected responses and verify parameters to AWS client
			setupIssueCertificate(client, clk, expectPem, tt.issuedCertErr)
			setupWaitUntilCertificateIssued(t, p, tt.waitCertErr)
			setupGetCertificate(client, tt.getCertificateCert, tt.getCertificateCertChain, tt.getCertificateErr)

			x509CA, x509Authorities, stream, err := ua.MintX509CA(context.Background(), tt.csr, tt.preferredTTL)
			spiretest.RequireGRPCStatusHasPrefix(t, err, tt.expectCode, tt.expectMsgPrefix)
			if tt.expectCode != codes.OK {
				assert.Nil(t, x509CA, "no x509CA expected")
				assert.Nil(t, x509Authorities, "no x509Authorities expected")
				assert.Nil(t, stream, "no stream expected")
				return
			}

			assert.Equal(t, tt.expectX509CA, x509CA, "unexpected X509CA")
			assert.Equal(t, tt.expectX509Authorities, x509Authorities, "unexected authorities")

			// Plugin does not support streaming back changes so assert the
			// stream returns EOF.
			_, streamErr := stream.RecvUpstreamX509Authorities()
			assert.True(t, errors.Is(streamErr, io.EOF))
		})
	}
}

func TestPublishJWTKey(t *testing.T) {
	client := &pcaClientFake{t: t}

	// Configure plugin
	setupDescribeCertificateAuthority(client, "ACTIVE", nil)
	p := New()
	p.hooks.newClient = func(ctx context.Context, config *Configuration) (PCAClient, error) {
		return client, nil
	}
	setupWaitUntilCertificateIssued(t, p, nil)

	ua := new(upstreamauthority.V1)
	var err error
	plugintest.Load(t, builtin(p), ua,
		plugintest.CaptureConfigureError(&err),
		plugintest.ConfigureJSON(&Configuration{
			Region:                  validRegion,
			CertificateAuthorityARN: validCertificateAuthorityARN,
			CASigningTemplateARN:    validCASigningTemplateARN,
			SigningAlgorithm:        validSigningAlgorithm,
			AssumeRoleARN:           validAssumeRoleARN,
			SupplementalBundlePath:  "",
		}),
	)
	require.NoError(t, err)

	pkixBytes, err := x509.MarshalPKIXPublicKey(testkey.NewEC256(t).Public())
	require.NoError(t, err)

	jwtAuthorities, stream, err := ua.PublishJWTKey(context.Background(), &common.PublicKey{Kid: "ID", PkixBytes: pkixBytes})
	spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, "upstreamauthority(aws_pca): publishing upstream is unsupported")
	assert.Nil(t, jwtAuthorities)
	assert.Nil(t, stream)
}

func setupDescribeCertificateAuthority(client *pcaClientFake, status string, err error) {
	client.expectedDescribeInput = &acmpca.DescribeCertificateAuthorityInput{
		CertificateAuthorityArn: aws.String(validCertificateAuthorityARN),
	}
	client.describeCertificateErr = err

	client.describeCertificateOutput = &acmpca.DescribeCertificateAuthorityOutput{
		CertificateAuthority: &acmpcatypes.CertificateAuthority{
			CertificateAuthorityConfiguration: &acmpcatypes.CertificateAuthorityConfiguration{
				SigningAlgorithm: acmpcatypes.SigningAlgorithm("defaultSigningAlgorithm"),
			},
			// For all possible statuses, see:
			// https://docs.aws.amazon.com/cli/latest/reference/acm-pca/describe-certificate-authority.html
			Status: acmpcatypes.CertificateAuthorityStatus(status),
		},
	}
}

func setupIssueCertificate(client *pcaClientFake, clk clock.Clock, csr []byte, err error) {
	client.expectedIssueInput = &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(validCertificateAuthorityARN),
		SigningAlgorithm:        acmpcatypes.SigningAlgorithm(validSigningAlgorithm),
		Csr:                     csr,
		TemplateArn:             aws.String(validCASigningTemplateARN),
		Validity: &acmpcatypes.Validity{
			Type:  acmpcatypes.ValidityPeriodTypeAbsolute,
			Value: aws.Int64(clk.Now().Add(time.Second * testTTL).Unix()),
		},
	}
	client.issueCertificateErr = err
	client.issueCertificateOutput = &acmpca.IssueCertificateOutput{
		CertificateArn: aws.String("certificateArn"),
	}
}

func setupWaitUntilCertificateIssued(t testing.TB, p *PCAPlugin, err error) {
	expectedGetCertificateInput := &acmpca.GetCertificateInput{
		CertificateAuthorityArn: aws.String(validCertificateAuthorityARN),
		CertificateArn:          aws.String("certificateArn"),
	}

	p.hooks.waitRetryFn = certificateIssuedWaitRetryFunc(func(ctx context.Context, input *acmpca.GetCertificateInput, output *acmpca.GetCertificateOutput, innerErr error) (bool, error) {
		require.Equal(t, expectedGetCertificateInput, input)
		return false, err
	})
}

func setupGetCertificate(client *pcaClientFake, encodedCert string, encodedCertChain string, err error) {
	client.expectedGetCertificateInput = &acmpca.GetCertificateInput{
		CertificateAuthorityArn: aws.String(validCertificateAuthorityARN),
		CertificateArn:          aws.String("certificateArn"),
	}
	client.getCertificateErr = err
	client.getCertificateOutput = &acmpca.GetCertificateOutput{
		Certificate:      aws.String(encodedCert),
		CertificateChain: aws.String(encodedCertChain),
	}
}

func certificateAuthorityFixture(t *testing.T) (*x509.Certificate, *bytes.Buffer) {
	ca, _, err := util.LoadCAFixture()
	require.NoError(t, err)
	encodedCA := new(bytes.Buffer)
	err = pem.Encode(encodedCA, &pem.Block{
		Type:  certificateType,
		Bytes: ca.Raw,
	})
	require.NoError(t, err)
	return ca, encodedCA
}

func svidFixture(t *testing.T) (*x509.Certificate, *bytes.Buffer) {
	cert, _, err := util.LoadSVIDFixture()
	require.NoError(t, err)
	encodedCert := new(bytes.Buffer)
	err = pem.Encode(encodedCert, &pem.Block{
		Type:  certificateType,
		Bytes: cert.Raw,
	})
	require.NoError(t, err)
	return cert, encodedCert
}

func awsErr(code, status string, err error) error {
	return fmt.Errorf("%s: %s\ncaused by: %w", code, status, err)
}
