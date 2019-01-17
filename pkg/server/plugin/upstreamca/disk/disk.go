package disk

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/hashicorp/hcl"

	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/upstreamca"
)

type Configuration struct {
	TTL          string `hcl:"ttl" json:"ttl"` // time to live for generated certs
	CertFilePath string `hcl:"cert_file_path" json:"cert_file_path"`
	KeyFilePath  string `hcl:"key_file_path" json:"key_file_path"`
}

type diskPlugin struct {
	serialNumber x509util.SerialNumber

	mtx        sync.RWMutex
	cert       *x509.Certificate
	upstreamCA *x509svid.UpstreamCA
}

func (m *diskPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
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

	keyPEM, err := ioutil.ReadFile(config.KeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read %s: %s", config.KeyFilePath, err)
	}

	block, rest := pem.Decode(keyPEM)

	if block == nil {
		return nil, errors.New("invalid key format")
	}

	if len(rest) > 0 {
		return nil, errors.New("invalid key format: too many keys")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	certPEM, err := ioutil.ReadFile(config.CertFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read %s: %s", config.CertFilePath, err)
	}

	block, rest = pem.Decode(certPEM)

	if block == nil {
		return nil, errors.New("invalid cert format")
	}

	if len(rest) > 0 {
		return nil, errors.New("invalid cert format: too many certs")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
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

func (*diskPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (m *diskPlugin) SubmitCSR(ctx context.Context, request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
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
			CertChain:           cert.Raw,
			UpstreamTrustBundle: m.cert.Raw,
		},
	}, nil
}

func New() (m upstreamca.Plugin) {
	return &diskPlugin{
		serialNumber: x509util.NewSerialNumber(),
	}
}
