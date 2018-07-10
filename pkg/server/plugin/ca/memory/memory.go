package memory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"errors"
	"sync"
	"time"

	"github.com/hashicorp/hcl"

	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/ca"
)

var (
	pluginInfo = spi.GetPluginInfoResponse{
		Description: "",
		DateCreated: "",
		Version:     "",
		Author:      "",
		Company:     "",
	}
)

type certSubjectConfig struct {
	Country      []string
	Organization []string
	CommonName   string
}

type configuration struct {
	TrustDomain  string            `hcl:"trust_domain" json:"trust_domain"`
	BackdateSecs int               `hcl:"backdate_seconds" json:"backdate_seconds"`
	CertSubject  certSubjectConfig `hcl:"cert_subject" json:"cert_subject"`
	DefaultTTL   int               `hcl:"default_ttl" json:"default_ttl"`
}

type MemoryPlugin struct {
	serialNumber x509util.SerialNumber

	mtx sync.RWMutex
	// everything below is protected by the mutex
	config   *configuration
	newKey   *ecdsa.PrivateKey
	keypair  *x509util.MemoryKeypair
	serverCA *x509svid.ServerCA
}

func New() *MemoryPlugin {
	return &MemoryPlugin{
		serialNumber: x509util.NewSerialNumber(),
	}
}

func NewWithDefault() *MemoryPlugin {
	m := New()
	m.configure(&configuration{
		TrustDomain: "localhost",
		CertSubject: certSubjectConfig{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "",
		},
	})
	return m
}

func (m *MemoryPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &configuration{}
	if err := hcl.Decode(&config, req.Configuration); err != nil {
		return nil, err
	}
	if config.TrustDomain == "" {
		return nil, errors.New("trust domain is required")
	}

	m.configure(config)
	return &spi.ConfigureResponse{}, nil
}

func (m *MemoryPlugin) configure(config *configuration) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.config = config
	m.initializeCA()
}

func (m *MemoryPlugin) initializeCA() {
	if m.keypair == nil {
		m.serverCA = nil
		return
	}

	m.serverCA = x509svid.NewServerCA(m.keypair, m.config.TrustDomain,
		x509svid.ServerCAOptions{
			TTL:          time.Duration(m.config.DefaultTTL) * time.Second,
			Backdate:     time.Duration(m.config.BackdateSecs) * time.Second,
			SerialNumber: m.serialNumber,
		})
}

func (*MemoryPlugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (m *MemoryPlugin) SignCsr(ctx context.Context, request *ca.SignCsrRequest) (*ca.SignCsrResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.serverCA == nil {
		return nil, errors.New("invalid state: no certificate loaded")
	}

	cert, err := m.serverCA.SignCSR(ctx, request.Csr, time.Duration(request.Ttl)*time.Second)
	if err != nil {
		return nil, err
	}

	return &ca.SignCsrResponse{SignedCertificate: cert.Raw}, nil
}

func (m *MemoryPlugin) GenerateCsr(ctx context.Context, req *ca.GenerateCsrRequest) (*ca.GenerateCsrResponse, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	newKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, errors.New("generate private key: " + err.Error())
	}
	m.newKey = newKey

	csr, err := x509svid.GenerateServerCACSR(newKey, m.config.TrustDomain,
		x509svid.ServerCACSROptions{
			Subject: pkix.Name{
				Country:      m.config.CertSubject.Country,
				Organization: m.config.CertSubject.Organization,
				CommonName:   m.config.CertSubject.CommonName,
			},
		})

	return &ca.GenerateCsrResponse{Csr: csr}, nil
}

func (m *MemoryPlugin) FetchCertificate(ctx context.Context, request *ca.FetchCertificateRequest) (*ca.FetchCertificateResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.keypair == nil {
		// return empty result if uninitialized.
		return &ca.FetchCertificateResponse{}, nil
	}

	cert, err := m.keypair.GetCertificate(ctx)
	if err != nil {
		return nil, err
	}

	return &ca.FetchCertificateResponse{StoredIntermediateCert: cert.Raw}, nil
}

func (m *MemoryPlugin) LoadCertificate(ctx context.Context, request *ca.LoadCertificateRequest) (response *ca.LoadCertificateResponse, err error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.newKey == nil {
		return nil, errors.New("invalid state: no private key")
	}

	cert, err := x509svid.ParseAndValidateServerCACertificate(request.SignedIntermediateCert, m.config.TrustDomain)
	if err != nil {
		return nil, err
	}

	m.keypair = x509util.NewMemoryKeypair(cert, m.newKey)
	m.initializeCA()

	return &ca.LoadCertificateResponse{}, nil
}
