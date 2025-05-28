package awspca

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/x509util"
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
	// Max certificate issuance wait duration
	maxCertIssuanceWaitDur = 3 * time.Minute
)

type newACMPCAClientFunc func(context.Context, *Configuration) (PCAClient, error)
type certificateIssuedWaitRetryFunc func(context.Context, *acmpca.GetCertificateInput, *acmpca.GetCertificateOutput, error) (bool, error)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *PCAPlugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// Configuration provides configuration context for the plugin
type Configuration struct {
	Region                  string `hcl:"region" json:"region"`
	Endpoint                string `hcl:"endpoint" json:"endpoint"`
	CertificateAuthorityARN string `hcl:"certificate_authority_arn" json:"certificate_authority_arn"`
	SigningAlgorithm        string `hcl:"signing_algorithm" json:"signing_algorithm"`
	CASigningTemplateARN    string `hcl:"ca_signing_template_arn" json:"ca_signing_template_arn"`
	AssumeRoleARN           string `hcl:"assume_role_arn" json:"assume_role_arn"`
	SupplementalBundlePath  string `hcl:"supplemental_bundle_path" json:"supplemental_bundle_path"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Configuration {
	newConfig := new(Configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportError("plugin configuration is malformed")
		return nil
	}
	if newConfig.Region == "" {
		status.ReportError("plugin configuration is missing the region")
	}
	if newConfig.CertificateAuthorityARN == "" {
		status.ReportError("plugin configuration is missing the certificate_authority_arn")
	}

	return newConfig
}

// PCAPlugin is the main representation of this upstreamauthority plugin
type PCAPlugin struct {
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

	log hclog.Logger

	mtx       sync.Mutex
	pcaClient PCAClient
	config    *configuration

	hooks struct {
		clock       clock.Clock
		newClient   newACMPCAClientFunc
		waitRetryFn certificateIssuedWaitRetryFunc
	}
}

type configuration struct {
	certificateAuthorityArn string
	signingAlgorithm        string
	caSigningTemplateArn    string
	supplementalBundle      []*x509.Certificate
}

// New returns an instantiated plugin
func New() *PCAPlugin {
	return newPlugin(newPCAClient, nil)
}

func newPlugin(newClient newACMPCAClientFunc, waitRetryFn certificateIssuedWaitRetryFunc) *PCAPlugin {
	p := &PCAPlugin{}
	p.hooks.clock = clock.New()
	p.hooks.newClient = newClient
	p.hooks.waitRetryFn = waitRetryFn
	return p
}

func (p *PCAPlugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Configure sets up the plugin for use as an upstream authority
func (p *PCAPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	var supplementalBundle []*x509.Certificate
	if newConfig.SupplementalBundlePath != "" {
		p.log.Info("Loading supplemental certificates for inclusion in the bundle", "supplemental_bundle_path", newConfig.SupplementalBundlePath)
		supplementalBundle, err = pemutil.LoadCertificates(newConfig.SupplementalBundlePath)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to load supplemental bundle: %v", err)
		}
	}

	// Create the client
	pcaClient, err := p.hooks.newClient(ctx, newConfig)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create client: %v", err)
	}

	// Perform a check for the presence of the CA
	p.log.Info("Looking up certificate authority from ACM", "certificate_authority_arn", newConfig.CertificateAuthorityARN)
	describeResponse, err := pcaClient.DescribeCertificateAuthority(ctx, &acmpca.DescribeCertificateAuthorityInput{
		CertificateAuthorityArn: aws.String(newConfig.CertificateAuthorityARN),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to describe CertificateAuthority: %v", err)
	}

	// Ensure the CA is set to ACTIVE
	caStatus := describeResponse.CertificateAuthority.Status
	if caStatus != "ACTIVE" {
		p.log.Warn("Certificate is in an invalid state for issuance",
			"certificate_authority_arn", newConfig.CertificateAuthorityARN,
			"status", caStatus)
	}

	// If a signing algorithm has been provided, use it.
	// Otherwise, fall back to the pre-configured value on the CA
	signingAlgorithm := newConfig.SigningAlgorithm
	if signingAlgorithm == "" {
		signingAlgorithm = string(describeResponse.CertificateAuthority.CertificateAuthorityConfiguration.SigningAlgorithm)
		p.log.Info("No signing algorithm specified, using the CA default", "signing_algorithm", signingAlgorithm)
	}

	// If a CA signing template ARN has been provided, use it.
	// Otherwise, fall back to the default value (PathLen=0)
	caSigningTemplateArn := newConfig.CASigningTemplateARN
	if caSigningTemplateArn == "" {
		p.log.Info("No CA signing template ARN specified, using the default", "ca_signing_template_arn", defaultCASigningTemplateArn)
		caSigningTemplateArn = defaultCASigningTemplateArn
	}

	// Set local vars
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.pcaClient = pcaClient
	p.config = &configuration{
		supplementalBundle:      supplementalBundle,
		signingAlgorithm:        signingAlgorithm,
		caSigningTemplateArn:    caSigningTemplateArn,
		certificateAuthorityArn: newConfig.CertificateAuthorityARN,
	}

	return &configv1.ConfigureResponse{}, nil
}

func (p *PCAPlugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, err
}

// MintX509CA mints an X509CA by submitting the CSR to ACM to be signed by the certificate authority
func (p *PCAPlugin) MintX509CAAndSubscribe(request *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	ctx := stream.Context()

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	csrBuf := new(bytes.Buffer)
	if err := pem.Encode(csrBuf, &pem.Block{
		Type:  csrRequestType,
		Bytes: request.Csr,
	}); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to encode csr from request: %v", err)
	}

	// Have ACM sign the certificate
	p.log.Info("Submitting CSR to ACM", "signing_algorithm", config.signingAlgorithm)
	validityPeriod := time.Second * time.Duration(request.PreferredTtl)

	issueResponse, err := p.pcaClient.IssueCertificate(ctx, &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(config.certificateAuthorityArn),
		SigningAlgorithm:        acmpcatypes.SigningAlgorithm(config.signingAlgorithm),
		Csr:                     csrBuf.Bytes(),
		TemplateArn:             aws.String(config.caSigningTemplateArn),
		Validity: &acmpcatypes.Validity{
			Type:  acmpcatypes.ValidityPeriodTypeAbsolute,
			Value: aws.Int64(p.hooks.clock.Now().Add(validityPeriod).Unix()),
		},
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed submitting CSR: %v", err)
	}

	// Using the output of the `IssueCertificate` call, poll ACM until
	// the certificate has been issued
	certificateArn := issueResponse.CertificateArn

	p.log.Info("Waiting for issuance from ACM", "certificate_arn", aws.ToString(certificateArn))
	getCertificateInput := &acmpca.GetCertificateInput{
		CertificateAuthorityArn: aws.String(config.certificateAuthorityArn),
		CertificateArn:          certificateArn,
	}

	var certIssuedWaitOptFns []func(*acmpca.CertificateIssuedWaiterOptions)
	if p.hooks.waitRetryFn != nil {
		retryableOption := func(opts *acmpca.CertificateIssuedWaiterOptions) {
			opts.Retryable = p.hooks.waitRetryFn
		}
		certIssuedWaitOptFns = append(certIssuedWaitOptFns, retryableOption)
	}

	waiter := acmpca.NewCertificateIssuedWaiter(p.pcaClient, certIssuedWaitOptFns...)
	if err := waiter.Wait(ctx, getCertificateInput, maxCertIssuanceWaitDur); err != nil {
		return status.Errorf(codes.Internal, "failed waiting for issuance: %v", err)
	}
	p.log.Info("Certificate issued", "certificate_arn", aws.ToString(certificateArn))

	// Finally get the certificate contents
	p.log.Info("Retrieving certificate and chain from ACM", "certificate_arn", aws.ToString(certificateArn))
	getResponse, err := p.pcaClient.GetCertificate(ctx, getCertificateInput)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get certificates: %v", err)
	}

	// Parse the cert from the response
	cert, err := pemutil.ParseCertificate([]byte(aws.ToString(getResponse.Certificate)))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to parse certificate from response: %v", err)
	}

	// Parse the chain from the response
	certChain, err := pemutil.ParseCertificates([]byte(aws.ToString(getResponse.CertificateChain)))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to parse certificate chain from response: %v", err)
	}
	p.log.Info("Certificate and chain received", "certificate_arn", aws.ToString(certificateArn))

	// ACM's API outputs the certificate chain from a GetCertificate call in the following
	// order: A (signed by B) -> B (signed by ROOT) -> ROOT.
	// For SPIRE, the certificate chain will always include at least one certificate (the root),
	// but may include other intermediates between SPIRE and the ROOT.
	// See https://docs.aws.amazon.com/cli/latest/reference/acm-pca/import-certificate-authority-certificate.html
	// and https://docs.aws.amazon.com/cli/latest/reference/acm-pca/get-certificate.html

	// The last certificate returned from the chain is the root.
	upstreamRoot := certChain[len(certChain)-1]
	bundle := x509util.DedupeCertificates([]*x509.Certificate{upstreamRoot}, config.supplementalBundle)

	upstreamX509Roots, err := x509certificate.ToPluginFromCertificates(bundle)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response upstream X.509 roots: %v", err)
	}

	// All else comprises the chain (including the issued certificate)
	x509CAChain, err := x509certificate.ToPluginFromCertificates(append([]*x509.Certificate{cert}, certChain[:len(certChain)-1]...))
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response X.509 CA chain: %v", err)
	}

	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       x509CAChain,
		UpstreamX509Roots: upstreamX509Roots,
	})
}

// PublishJWTKey is not implemented by the wrapper and returns a codes.Unimplemented status
func (*PCAPlugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

func (p *PCAPlugin) SubscribeToLocalBundle(req *upstreamauthorityv1.SubscribeToLocalBundleRequest, stream upstreamauthorityv1.UpstreamAuthority_SubscribeToLocalBundleServer) error {
	return status.Error(codes.Unimplemented, "fetching upstream trust bundle is unsupported")
}

func (p *PCAPlugin) getConfig() (*configuration, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
