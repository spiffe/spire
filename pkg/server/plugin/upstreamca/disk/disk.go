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
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/upstreamca"
)

func BuiltIn() catalog.Plugin {
	return builtIn(New())
}

func builtIn(p *DiskPlugin) catalog.Plugin {
	return catalog.MakePlugin("disk",
		upstreamca.PluginServer(p),
	)
}

type Configuration struct {
	TTL          string `hcl:"ttl" json:"ttl"` // time to live for generated certs
	CertFilePath string `hcl:"cert_file_path" json:"cert_file_path"`
	KeyFilePath  string `hcl:"key_file_path" json:"key_file_path"`
}

type DiskPlugin struct {
	serialNumber x509util.SerialNumber

	mtx        sync.RWMutex
	cert       *x509.Certificate
	upstreamCA *x509svid.UpstreamCA
}

func New() *DiskPlugin {
	return &DiskPlugin{
		serialNumber: x509util.NewSerialNumber(),
	}
}

func (m *DiskPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
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

	key, err := pemutil.LoadPrivateKey(config.KeyFilePath)
	if err != nil {
		return nil, err
	}

	cert, err := pemutil.LoadCertificate(config.CertFilePath)
	if err != nil {
		return nil, err
	}

	// Validate cert matches private key
	matched, err := x509util.CertificateMatchesPrivateKey(cert, key)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, errors.New("certificate and private key does not match")
	}

	ttl, err := time.ParseDuration(config.TTL)
	if err != nil {
		return nil, fmt.Errorf("invalid TTL value: %v", err)
	}

	// Set local vars from config struct
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.cert = cert
	m.upstreamCA = x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(cert, key),
		req.GlobalConfig.TrustDomain,
		x509svid.UpstreamCAOptions{
			SerialNumber: m.serialNumber,
			TTL:          ttl,
		})

	return &spi.ConfigureResponse{}, nil
}

func (*DiskPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (m *DiskPlugin) SubmitCSR(ctx context.Context, request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.upstreamCA == nil {
		return nil, errors.New("invalid state: not configured")
	}

	cert, err := m.upstreamCA.SignCSR(ctx, request.Csr)
	if err != nil {
		return nil, err
	}

	return &upstreamca.SubmitCSRResponse{
		SignedCertificate: &upstreamca.SignedCertificate{
			CertChain: cert.Raw,
			Bundle:    m.cert.Raw,
		},
	}, nil
}
