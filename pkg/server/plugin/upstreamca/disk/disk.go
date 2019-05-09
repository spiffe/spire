package disk

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/hcl"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/upstreamca"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *DiskPlugin) catalog.Plugin {
	return catalog.MakePlugin("disk",
		upstreamca.PluginServer(p),
	)
}

type Configuration struct {
	trustDomain string
	ttl         time.Duration

	TTL          string `hcl:"ttl" json:"ttl"` // time to live for generated certs
	CertFilePath string `hcl:"cert_file_path" json:"cert_file_path"`
	KeyFilePath  string `hcl:"key_file_path" json:"key_file_path"`
}

type DiskPlugin struct {
	serialNumber x509util.SerialNumber

	mtx        sync.Mutex
	cert       *x509.Certificate
	config     *Configuration
	upstreamCA *x509svid.UpstreamCA
}

func New() *DiskPlugin {
	return &DiskPlugin{
		serialNumber: x509util.NewSerialNumber(),
	}
}

func (p *DiskPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
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

	ttl, err := time.ParseDuration(config.TTL)
	if err != nil {
		return nil, fmt.Errorf("invalid TTL value: %v", err)
	}

	config.ttl = ttl
	config.trustDomain = req.GlobalConfig.TrustDomain

	upstreamCA, cert, err := p.loadUpstreamCAAndCert(config)
	if err != nil {
		return nil, fmt.Errorf("failed to load upstream CA: %v", err)
	}

	// Set local vars from config struct
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config
	p.cert = cert
	p.upstreamCA = upstreamCA

	return &spi.ConfigureResponse{}, nil
}

func (*DiskPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *DiskPlugin) SubmitCSR(ctx context.Context, request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	upstreamCA, upstreamCert, err := p.reloadCA()
	if err != nil {
		return nil, err
	}

	cert, err := upstreamCA.SignCSR(ctx, request.Csr)
	if err != nil {
		return nil, err
	}

	return &upstreamca.SubmitCSRResponse{
		SignedCertificate: &upstreamca.SignedCertificate{
			CertChain: cert.Raw,
			Bundle:    upstreamCert.Raw,
		},
	}, nil
}

func (p *DiskPlugin) reloadCA() (*x509svid.UpstreamCA, *x509.Certificate, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	upstreamCA, upstreamCert, err := p.loadUpstreamCAAndCert(p.config)
	switch {
	case err == nil:
		p.upstreamCA = upstreamCA
		p.cert = upstreamCert
	case p.upstreamCA != nil:
		upstreamCA = p.upstreamCA
		upstreamCert = p.cert
	default:
		return nil, nil, fmt.Errorf("no cached CA and failed to load CA: %v", err)
	}

	return upstreamCA, upstreamCert, nil
}

func (p *DiskPlugin) loadUpstreamCAAndCert(config *Configuration) (*x509svid.UpstreamCA, *x509.Certificate, error) {
	key, err := pemutil.LoadPrivateKey(config.KeyFilePath)
	if err != nil {
		return nil, nil, err
	}

	cert, err := pemutil.LoadCertificate(config.CertFilePath)
	if err != nil {
		return nil, nil, err
	}

	// Validate cert matches private key
	matched, err := x509util.CertificateMatchesPrivateKey(cert, key)
	if err != nil {
		return nil, nil, err
	}
	if !matched {
		return nil, nil, errors.New("certificate and private key does not match")
	}

	return x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(cert, key),
		config.trustDomain,
		x509svid.UpstreamCAOptions{
			SerialNumber: p.serialNumber,
			TTL:          config.ttl,
		},
	), cert, nil
}
