package awspca

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/acmpca"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// The name of the plugin
	pluginName = "aws_pca"
	// The header and footer type for a PEM-encoded CSR
	csrRequestType = "CERTIFICATE REQUEST"
	// The default CA signing template to use.
	// The SPIRE server intermediate CA can sign end-entity SVIDs only.
	defaultCASigningTemplateArn = "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *PCAPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName,
		upstreamauthority.PluginServer(p),
	)
}

// PCAPluginConfiguration provides configuration context for the plugin
type PCAPluginConfiguration struct {
	Region                  string `hcl:"region" json:"region"`
	CertificateAuthorityARN string `hcl:"certificate_authority_arn" json:"certificate_authority_arn"`
	SigningAlgorithm        string `hcl:"signing_algorithm" json:"signing_algorithm"`
	CASigningTemplateARN    string `hcl:"ca_signing_template_arn" json:"ca_signing_template_arn"`
	AssumeRoleARN           string `hcl:"assume_role_arn" json:"assume_role_arn"`
}

// PCAPlugin is the main representation of this upstreamauthority plugin
type PCAPlugin struct {
	log hclog.Logger

	pcaClient               PCAClient
	certificateAuthorityArn string
	signingAlgorithm        string
	caSigningTemplateArn    string

	hooks struct {
		clock     clock.Clock
		newClient func(config *PCAPluginConfiguration) (PCAClient, error)
	}
}

// New returns an instantiated plugin
func New() *PCAPlugin {
	return newPlugin(newPCAClient)
}

func newPlugin(newClient func(config *PCAPluginConfiguration) (PCAClient, error)) *PCAPlugin {
	p := &PCAPlugin{}
	p.hooks.clock = clock.New()
	p.hooks.newClient = newClient
	return p
}

func (m *PCAPlugin) SetLogger(log hclog.Logger) {
	m.log = log
}

// Configure sets up the plugin for use as an upstream authority
func (m *PCAPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config, err := m.validateConfig(req)
	if err != nil {
		return nil, err
	}

	// Create the client
	m.pcaClient, err = m.hooks.newClient(config)
	if err != nil {
		return nil, err
	}

	// Perform a check for the presence of the CA
	m.log.Info("Looking up certificate authority from ACM.", "certificate_authority_arn", config.CertificateAuthorityARN)
	describeResponse, err := m.pcaClient.DescribeCertificateAuthorityWithContext(ctx, &acmpca.DescribeCertificateAuthorityInput{
		CertificateAuthorityArn: aws.String(config.CertificateAuthorityARN),
	})
	if err != nil {
		return nil, err
	}

	// Ensure the CA is set to ACTIVE
	caStatus := aws.StringValue(describeResponse.CertificateAuthority.Status)
	if caStatus != "ACTIVE" {
		m.log.Warn("Certificate is in an invalid state for issuance.",
			"certificate_authority_arn", config.CertificateAuthorityARN,
			"status", caStatus)
	}

	// If a signing algorithm has been provided, use it.
	// Otherwise, fall back to the pre-configured value on the CA
	if config.SigningAlgorithm != "" {
		m.signingAlgorithm = config.SigningAlgorithm
	} else {
		signingAlgortithm := aws.StringValue(describeResponse.CertificateAuthority.CertificateAuthorityConfiguration.SigningAlgorithm)
		m.log.Info("No signing algorithm specified, using the CA default.", "signing_algorithm", signingAlgortithm)
		m.signingAlgorithm = signingAlgortithm
	}

	// If a CA signing template ARN has been provided, use it.
	// Otherwise, fall back to the default value (PathLen=0)
	if config.CASigningTemplateARN != "" {
		m.caSigningTemplateArn = config.CASigningTemplateARN
	} else {
		m.log.Info("No CA signing template ARN specified, using the default.", "ca_signing_template_arn", defaultCASigningTemplateArn)
		m.caSigningTemplateArn = defaultCASigningTemplateArn
	}

	// Add remaining values to plugin
	m.certificateAuthorityArn = config.CertificateAuthorityARN

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns information about this plugin to Spire server
func (*PCAPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// MintX509CA mints an X509CA by submitting the CSR to ACM to be signed by the certificate authority
func (m *PCAPlugin) MintX509CA(request *upstreamauthority.MintX509CARequest, stream upstreamauthority.UpstreamAuthority_MintX509CAServer) error {
	ctx := stream.Context()

	csrBuf := new(bytes.Buffer)
	err := pem.Encode(csrBuf, &pem.Block{
		Type:  csrRequestType,
		Bytes: request.Csr,
	})
	if err != nil {
		return err
	}

	// Have ACM sign the certificate
	m.log.Info("Submitting CSR to ACM.", "signing_algorithm", m.signingAlgorithm)
	validityPeriod := time.Second * time.Duration(request.PreferredTtl)
	issueResponse, err := m.pcaClient.IssueCertificateWithContext(ctx, &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(m.certificateAuthorityArn),
		SigningAlgorithm:        aws.String(m.signingAlgorithm),
		Csr:                     csrBuf.Bytes(),
		TemplateArn:             aws.String(m.caSigningTemplateArn),
		Validity: &acmpca.Validity{
			Type:  aws.String(acmpca.ValidityPeriodTypeAbsolute),
			Value: aws.Int64(m.hooks.clock.Now().Add(validityPeriod).Unix()),
		},
	})

	if err != nil {
		return err
	}

	// Using the output of the `IssueCertificate` call, poll ACM until
	// the certificate has been issued
	certificateArn := issueResponse.CertificateArn

	m.log.Info("Waiting for issuance from ACM.", "certificate_arn", aws.StringValue(certificateArn))
	getCertificateInput := &acmpca.GetCertificateInput{
		CertificateAuthorityArn: aws.String(m.certificateAuthorityArn),
		CertificateArn:          certificateArn,
	}
	err = m.pcaClient.WaitUntilCertificateIssuedWithContext(ctx, getCertificateInput)
	if err != nil {
		return err
	}
	m.log.Info("Certificate issued.", "certificate_arn", aws.StringValue(certificateArn))

	// Finally get the certificate contents
	m.log.Info("Retrieving certificate and chain from ACM.", "certificate_arn", aws.StringValue(certificateArn))
	getResponse, err := m.pcaClient.GetCertificateWithContext(ctx, getCertificateInput)
	if err != nil {
		return err
	}

	// Parse the cert from the response
	cert, err := pemutil.ParseCertificate([]byte(aws.StringValue(getResponse.Certificate)))
	if err != nil {
		return err
	}

	// Parse the chain from the response
	certChain, err := pemutil.ParseCertificates([]byte(aws.StringValue(getResponse.CertificateChain)))
	if err != nil {
		return err
	}
	m.log.Info("Certificate and chain received.", "certificate_arn", aws.StringValue(certificateArn))

	// ACM's API outputs the certificate chain from a GetCertificate call in the following
	// order: A (signed by B) -> B (signed by ROOT) -> ROOT.
	// For SPIRE, the certificate chain will always include at least one certificate (the root),
	// but may include other intermediates between SPIRE and the ROOT.
	// See https://docs.aws.amazon.com/cli/latest/reference/acm-pca/import-certificate-authority-certificate.html
	// and https://docs.aws.amazon.com/cli/latest/reference/acm-pca/get-certificate.html

	// The last certificate returned from the chain is the bundle.
	bundle := [][]byte{certChain[len(certChain)-1].Raw}

	// All else comprises the chain (including the issued certificate)
	chain := [][]byte{cert.Raw}
	for _, caCert := range certChain[:len(certChain)-1] {
		chain = append(chain, caCert.Raw)
	}

	return stream.Send(&upstreamauthority.MintX509CAResponse{
		X509CaChain:       chain,
		UpstreamX509Roots: bundle,
	})
}

// validateConfig returns an error if any configuration provided does not meet acceptable criteria
func (m *PCAPlugin) validateConfig(req *spi.ConfigureRequest) (*PCAPluginConfiguration, error) {
	config := new(PCAPluginConfiguration)

	if err := hcl.Decode(&config, req.Configuration); err != nil {
		return nil, err
	}

	if config.Region == "" {
		return nil, errors.New("configuration is missing a region")
	}

	if config.CertificateAuthorityARN == "" {
		return nil, errors.New("configuration is missing a certificate authority ARN")
	}

	return config, nil
}

// PublishJWTKey is not implemented by the wrapper and returns a codes.Unimplemented status
func (m *PCAPlugin) PublishJWTKey(*upstreamauthority.PublishJWTKeyRequest, upstreamauthority.UpstreamAuthority_PublishJWTKeyServer) error {
	return makeError(codes.Unimplemented, "publishing upstream is unsupported")
}

func makeError(code codes.Code, format string, args ...interface{}) error {
	return status.Errorf(code, "aws-pca: "+format, args...)
}
