package disk

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/andres-erbsen/clock"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
)

const (
	CoreConfigRequired             = "server core configuration is required"
	CoreConfigTrustDomainRequired  = "server core configuration must contain trust_domain"
	CoreConfigTrustDomainMalformed = "server core configuration trust_domain is malformed"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn("disk",
		upstreamauthorityv1.UpstreamAuthorityPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type Configuration struct {
	trustDomain spiffeid.TrustDomain

	CertFilePath   string `hcl:"cert_file_path" json:"cert_file_path"`
	KeyFilePath    string `hcl:"key_file_path" json:"key_file_path"`
	BundleFilePath string `hcl:"bundle_file_path" json:"bundle_file_path"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *Configuration {
	newConfig := new(Configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportError("plugin configuration is malformed")
		return nil
	}

	newConfig.trustDomain = coreConfig.TrustDomain
	// TODO: add field validation

	return newConfig
}

type Plugin struct {
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

	log hclog.Logger

	mtx        sync.Mutex
	config     *Configuration
	certs      *caCerts
	upstreamCA *x509svid.UpstreamCA

	// test hooks
	clock clock.Clock
}

type caCerts struct {
	certChain   []*x509.Certificate
	trustBundle []*x509.Certificate
}

func New() *Plugin {
	return &Plugin{
		clock: clock.New(),
	}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	upstreamCA, certs, err := p.loadUpstreamCAAndCerts(newConfig)
	if err != nil {
		return nil, err
	}

	// Set local vars from config struct
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = newConfig
	p.certs = certs
	p.upstreamCA = upstreamCA

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, err
}

func (p *Plugin) MintX509CAAndSubscribe(request *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	ctx := stream.Context()

	upstreamCA, upstreamCerts, err := p.reloadCA()
	if err != nil {
		return err
	}

	cert, err := upstreamCA.SignCSR(ctx, request.Csr, time.Second*time.Duration(request.PreferredTtl))
	if err != nil {
		// TODO: provide more granular status codes
		return status.Errorf(codes.Internal, "unable to sign CSR: %v", err)
	}

	x509CAChain, err := x509certificate.ToPluginFromCertificates(append([]*x509.Certificate{cert}, upstreamCerts.certChain...))
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response X.509 CA chain: %v", err)
	}

	upstreamX509Roots, err := x509certificate.ToPluginFromCertificates(upstreamCerts.trustBundle)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response upstream X.509 roots: %v", err)
	}

	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       x509CAChain,
		UpstreamX509Roots: upstreamX509Roots,
	})
}

func (*Plugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

func (p *Plugin) SubscribeToLocalBundle(req *upstreamauthorityv1.SubscribeToLocalBundleRequest, stream upstreamauthorityv1.UpstreamAuthority_SubscribeToLocalBundleServer) error {
	return status.Error(codes.Unimplemented, "fetching upstream trust bundle is unsupported")
}

func (p *Plugin) reloadCA() (*x509svid.UpstreamCA, *caCerts, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	upstreamCA, upstreamCerts, err := p.loadUpstreamCAAndCerts(p.config)
	switch {
	case err == nil:
		p.upstreamCA = upstreamCA
		p.certs = upstreamCerts
	case p.upstreamCA != nil:
		upstreamCA = p.upstreamCA
		upstreamCerts = p.certs
	default:
		return nil, nil, fmt.Errorf("no cached CA and failed to load CA: %w", err)
	}

	return upstreamCA, upstreamCerts, nil
}

// TODO: perhaps load this into the config
func (p *Plugin) loadUpstreamCAAndCerts(config *Configuration) (*x509svid.UpstreamCA, *caCerts, error) {
	key, err := pemutil.LoadPrivateKey(config.KeyFilePath)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to load upstream CA key: %v", err)
	}

	certs, err := pemutil.LoadCertificates(config.CertFilePath)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "unable to load upstream CA cert: %v", err)
	}
	// pemutil guarantees at least 1 cert
	caCert := certs[0]

	var trustBundle []*x509.Certificate
	if config.BundleFilePath == "" {
		// If there is no bundle path configured then we assume we have
		// a self-signed cert. We enforce this by requiring that there is
		// exactly one cert. This cert is reused for the trust bundle and
		// config.BundleFilePath is ignored
		if len(certs) != 1 {
			return nil, nil, status.Error(codes.InvalidArgument, "with no bundle_file_path configured only self-signed CAs are supported")
		}
		trustBundle = certs
		certs = nil
	} else {
		bundleCerts, err := pemutil.LoadCertificates(config.BundleFilePath)
		if err != nil {
			return nil, nil, status.Errorf(codes.InvalidArgument, "unable to load upstream CA bundle: %v", err)
		}
		trustBundle = append(trustBundle, bundleCerts...)
	}

	// Validate cert matches private key
	matched, err := x509util.CertificateMatchesPrivateKey(caCert, key)
	if err != nil {
		return nil, nil, err
	}
	if !matched {
		return nil, nil, status.Error(codes.InvalidArgument, "unable to load upstream CA: certificate and private key do not match")
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
		return nil, nil, status.Error(codes.InvalidArgument, "unable to load upstream CA: certificate cannot be validated with the provided bundle or is not self-signed")
	}

	caCerts := &caCerts{
		certChain:   certs,
		trustBundle: trustBundle,
	}

	return x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(caCert, key),
		config.trustDomain,
		x509svid.UpstreamCAOptions{
			Clock: p.clock,
		},
	), caCerts, nil
}
