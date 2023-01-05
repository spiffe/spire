package awssecret

import (
	"context"
	"crypto/x509"
	"os"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "awssecret"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type Configuration struct {
	Region          string `hcl:"region" json:"region"`
	CertFileARN     string `hcl:"cert_file_arn" json:"cert_file_arn"`
	KeyFileARN      string `hcl:"key_file_arn" json:"key_file_arn"`
	BundleFileARN   string `hcl:"bundle_file_arn" json:"bundle_file_arn"`
	AccessKeyID     string `hcl:"access_key_id" json:"access_key_id"`
	SecretAccessKey string `hcl:"secret_access_key" json:"secret_access_key"`
	SecurityToken   string `hcl:"secret_token" json:"secret_token"`
	AssumeRoleARN   string `hcl:"assume_role_arn" json:"assume_role_arn"`
}

type Plugin struct {
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

	log hclog.Logger

	mtx           sync.RWMutex
	upstreamCerts []*x509.Certificate
	bundleCerts   []*x509.Certificate
	upstreamCA    *x509svid.UpstreamCA

	hooks struct {
		clock     clock.Clock
		getenv    func(string) string
		newClient func(ctx context.Context, config *Configuration, region string) (secretsManagerClient, error)
	}
}

func New() *Plugin {
	return newPlugin(newSecretsManagerClient)
}

func newPlugin(newClient func(ctx context.Context, config *Configuration, region string) (secretsManagerClient, error)) *Plugin {
	p := &Plugin{}
	p.hooks.clock = clock.New()
	p.hooks.getenv = os.Getenv
	p.hooks.newClient = newClient
	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := p.validateConfig(req)
	if err != nil {
		return nil, err
	}

	// set the AWS configuration and reset clients +
	// Set local vars from config struct
	sm, err := p.hooks.newClient(ctx, config, config.Region)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to create AWS client: %v", err)
	}

	keyPEMstr, certsPEMstr, bundleCertsPEMstr, err := fetchFromSecretsManager(ctx, config, sm)
	if err != nil {
		p.log.Error("Error loading files from AWS: %v", err)
		return nil, err
	}

	trustDomain, err := spiffeid.TrustDomainFromString(req.CoreConfiguration.TrustDomain)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "trust_domain is malformed: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	upstreamCA, upstreamCerts, bundleCerts, err := p.loadUpstreamCAAndCerts(
		trustDomain, keyPEMstr, certsPEMstr, bundleCertsPEMstr,
	)
	if err != nil {
		return nil, err
	}

	p.upstreamCerts = upstreamCerts
	p.bundleCerts = bundleCerts
	p.upstreamCA = upstreamCA

	return &configv1.ConfigureResponse{}, nil
}

// MintX509CAAndSubscribe mints an X509CA by signing presented CSR with root CA fetched from AWS Secrets Manager
func (p *Plugin) MintX509CAAndSubscribe(request *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	ctx := stream.Context()
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.upstreamCA == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	cert, err := p.upstreamCA.SignCSR(ctx, request.Csr, time.Second*time.Duration(request.PreferredTtl))
	if err != nil {
		return status.Errorf(codes.Internal, "unable to sign CSR: %v", err)
	}

	x509CAChain, err := x509certificate.ToPluginProtos(append([]*x509.Certificate{cert}, p.upstreamCerts...))
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response X.509 CA chain: %v", err)
	}

	upstreamX509Roots, err := x509certificate.ToPluginProtos(p.bundleCerts)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response upstream X.509 roots: %v", err)
	}

	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       x509CAChain,
		UpstreamX509Roots: upstreamX509Roots,
	})
}

// PublishJWTKeyAndSubscribe is not implemented by the wrapper and returns a codes.Unimplemented status
func (p *Plugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

func (p *Plugin) loadUpstreamCAAndCerts(trustDomain spiffeid.TrustDomain, keyPEMstr, certsPEMstr, bundleCertsPEMstr string) (*x509svid.UpstreamCA, []*x509.Certificate, []*x509.Certificate, error) {
	key, err := pemutil.ParsePrivateKey([]byte(keyPEMstr))
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Internal, "unable to parse private key: %v", err)
	}

	certs, err := pemutil.ParseCertificates([]byte(certsPEMstr))
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.Internal, "unable to parse certificate: %v", err)
	}

	caCert := certs[0] // pemutil guarantees at least one cert

	var trustBundle []*x509.Certificate
	if bundleCertsPEMstr == "" {
		// If there is no bundle payload configured then the value of certs
		// must be a self-signed cert. We enforce this by requiring that there is
		// exactly one certificate; this certificate is reused for the trust
		// bundle and bundleCertsPEMstr is ignored
		if len(certs) != 1 {
			return nil, nil, nil, status.Error(codes.InvalidArgument, "with no bundle_file_arn configured only self-signed CAs are supported")
		}
		trustBundle = certs
		certs = nil
	} else {
		// If there is a bundle, instead of using the payload of cert_file_arn
		// to populate the trust bundle, we assume that certs is a chain of
		// intermediates and populate the trust bundle with roots from
		// bundle_file_arn
		trustBundle, err = pemutil.ParseCertificates([]byte(bundleCertsPEMstr))
		if err != nil {
			return nil, nil, nil, status.Errorf(codes.InvalidArgument, "unable to load upstream CA bundle: %v", err)
		}
	}

	matched, err := x509util.CertificateMatchesPrivateKey(caCert, key)
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.InvalidArgument, "unable to verify CA cert matches private key: %v", err)
	}
	if !matched {
		return nil, nil, nil, status.Error(codes.InvalidArgument, "unable to load upstream CA: certificate and private key do not match")
	}

	intermediates := x509.NewCertPool()
	roots := x509.NewCertPool()

	for _, c := range certs {
		intermediates.AddCert(c)
	}
	for _, c := range trustBundle {
		roots.AddCert(c)
	}
	selfVerifyOpts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	}
	_, err = caCert.Verify(selfVerifyOpts)
	if err != nil {
		return nil, nil, nil, status.Error(codes.InvalidArgument, "unable to load upstream CA: certificate could not be validated with the provided bundle or is not self signed")
	}

	// If we get to this point we've successfully validated that:
	// - cert_file_arn contains a single self-signed certificate OR
	// - cert_file_arn contains a chain of certificates which terminate at a root
	//   which is provided in bundle_file_arn
	return x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(caCert, key),
		trustDomain,
		x509svid.UpstreamCAOptions{
			Clock: p.hooks.clock,
		},
	), certs, trustBundle, nil
}

func fetchFromSecretsManager(ctx context.Context, config *Configuration, sm secretsManagerClient) (string, string, string, error) {
	keyPEMstr, err := readARN(ctx, sm, config.KeyFileARN)
	if err != nil {
		return "", "", "", status.Errorf(codes.InvalidArgument, "unable to read %s: %v", config.KeyFileARN, err)
	}

	certsPEMstr, err := readARN(ctx, sm, config.CertFileARN)
	if err != nil {
		return "", "", "", status.Errorf(codes.InvalidArgument, "unable to read %s: %v", config.CertFileARN, err)
	}
	var bundlePEMstr string
	if config.BundleFileARN != "" {
		bundlePEMstr, err = readARN(ctx, sm, config.BundleFileARN)
		if err != nil {
			return "", "", "", status.Errorf(codes.InvalidArgument, "unable to read %s: %v", config.BundleFileARN, err)
		}
	}

	return keyPEMstr, certsPEMstr, bundlePEMstr, nil
}

func (p *Plugin) validateConfig(req *configv1.ConfigureRequest) (*Configuration, error) {
	// Parse HCL config payload into config struct
	config := new(Configuration)

	if err := hcl.Decode(&config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}

	if req.CoreConfiguration.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	// Set defaults from the environment
	if config.SecurityToken == "" {
		config.SecurityToken = p.hooks.getenv("AWS_SESSION_TOKEN")
	}

	switch {
	case config.CertFileARN != "" && config.KeyFileARN != "":
	case config.CertFileARN != "" && config.KeyFileARN == "":
		return nil, status.Error(codes.InvalidArgument, "configuration missing key ARN")
	case config.CertFileARN == "" && config.KeyFileARN != "":
		return nil, status.Error(codes.InvalidArgument, "configuration missing cert ARN")
	case config.CertFileARN == "" && config.KeyFileARN == "":
		return nil, status.Error(codes.InvalidArgument, "configuration missing both cert ARN and key ARN")
	}

	return config, nil
}
