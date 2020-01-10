package disk

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"

	"github.com/andres-erbsen/clock"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamca"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *Plugin) catalog.Plugin {
	return catalog.MakePlugin("disk",
		upstreamca.PluginServer(p),
	)
}

type Configuration struct {
	trustDomain string
	ttl         time.Duration

	DeprecatedTTL  string `hcl:"ttl" json:"ttl"` // time to live for generated certs
	CertFilePath   string `hcl:"cert_file_path" json:"cert_file_path"`
	KeyFilePath    string `hcl:"key_file_path" json:"key_file_path"`
	BundleFilePath string `hcl:"bundle_file_path" json:"bundle_file_path"`
}

type Plugin struct {
	log   hclog.Logger
	clock clock.Clock

	_testOnlyShouldVerify bool

	mtx        sync.Mutex
	config     *Configuration
	certs      *caCerts
	upstreamCA *x509svid.UpstreamCA
}

type caCerts struct {
	certChain   []byte
	trustBundle []byte
}

func New() *Plugin {
	return &Plugin{
		clock:                 clock.New(),
		_testOnlyShouldVerify: true,
	}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &Configuration{}
	if err := hcl.Decode(&config, req.Configuration); err != nil {
		return nil, err
	}

	if req.GlobalConfig == nil {
		return nil, errors.New("global configuration is required")
	}

	if req.GlobalConfig.TrustDomain == "" {
		return nil, errors.New("trust_domain is required")
	}

	if config.DeprecatedTTL != "" {
		ttl, err := time.ParseDuration(config.DeprecatedTTL)
		if err != nil {
			return nil, fmt.Errorf("invalid TTL value: %v", err)
		}
		config.ttl = ttl
		p.log.Warn("Using deprecated ttl configurable. Use the server ca_ttl configurable instead.")
	}

	config.trustDomain = req.GlobalConfig.TrustDomain

	upstreamCA, certs, err := p.loadUpstreamCAAndCerts(config)
	if err != nil {
		return nil, fmt.Errorf("failed to load upstream CA: %v", err)
	}

	// Set local vars from config struct
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config
	p.certs = certs
	p.upstreamCA = upstreamCA

	return &spi.ConfigureResponse{}, nil
}

func (*Plugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *Plugin) SubmitCSR(ctx context.Context, request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	upstreamCA, upstreamCerts, err := p.reloadCA()
	if err != nil {
		return nil, err
	}

	cert, err := upstreamCA.SignCSR(ctx, request.Csr, time.Second*time.Duration(request.PreferredTtl))
	if err != nil {
		return nil, err
	}

	return &upstreamca.SubmitCSRResponse{
		SignedCertificate: &upstreamca.SignedCertificate{
			CertChain: append(cert.Raw, upstreamCerts.certChain...),
			Bundle:    upstreamCerts.trustBundle,
		},
	}, nil
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
		return nil, nil, fmt.Errorf("no cached CA and failed to load CA: %v", err)
	}

	return upstreamCA, upstreamCerts, nil
}

func (p *Plugin) loadUpstreamCAAndCerts(config *Configuration) (*x509svid.UpstreamCA, *caCerts, error) {
	key, err := pemutil.LoadPrivateKey(config.KeyFilePath)
	if err != nil {
		return nil, nil, err
	}

	certs, err := pemutil.LoadCertificates(config.CertFilePath)
	if err != nil {
		return nil, nil, err
	}
	// pemutil guarantees at least 1 cert
	caCert := certs[0]

	var trustBundle []*x509.Certificate
	if config.BundleFilePath == "" {
		// If there is no bundle path configured then we assume we have
		// a self signed cert. We enforce this by requiring that there is
		// exactly one cert. This cert is reused for the trust bundle and
		// config.BundleFilePath is ignored
		if len(certs) != 1 {
			return nil, nil, errors.New("with no bundle_file_path configured only self-signed CAs are supported")
		}
		trustBundle = certs
		certs = nil
	} else {
		bundleCerts, err := pemutil.LoadCertificates(config.BundleFilePath)
		if err != nil {
			return nil, nil, err
		}
		trustBundle = append(trustBundle, bundleCerts...)
	}

	// Validate cert matches private key
	matched, err := x509util.CertificateMatchesPrivateKey(caCert, key)
	if err != nil {
		return nil, nil, err
	}
	if !matched {
		return nil, nil, errors.New("certificate and private key does not match")
	}

	if p._testOnlyShouldVerify {
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
			return nil, nil, errors.New("certificate cannot be validated with the provided bundle or is not self-signed")
		}
	}

	caCerts := &caCerts{}
	for _, cert := range certs {
		caCerts.certChain = append(caCerts.certChain, cert.Raw...)
	}
	for _, cert := range trustBundle {
		caCerts.trustBundle = append(caCerts.trustBundle, cert.Raw...)
	}

	return x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(caCert, key),
		config.trustDomain,
		x509svid.UpstreamCAOptions{
			TTL:   config.ttl,
			Clock: p.clock,
		},
	), caCerts, nil
}
