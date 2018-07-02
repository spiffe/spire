package memory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/hcl"

	"github.com/spiffe/spire/pkg/common/jwtsvid"
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

type keypairs struct {
	x509Key  *ecdsa.PrivateKey
	x509Cert *x509.Certificate
	serverCA *x509svid.ServerCA
	jwtKey   *ecdsa.PrivateKey
	jwtCert  *x509.Certificate
}

type MemoryPlugin struct {
	serialNumber x509util.SerialNumber

	mtx     sync.RWMutex
	config  *configuration
	current *keypairs
	next    *keypairs

	// test hooks
	hooks struct {
		now func() time.Time
	}
}

var _ ca.ServerCA = (*MemoryPlugin)(nil)

func New() *MemoryPlugin {
	m := &MemoryPlugin{
		serialNumber: x509util.NewSerialNumber(),
	}
	m.hooks.now = time.Now
	return m
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
		return nil, fmt.Errorf("unable to decode configuration: %v", err)
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
	if m.current != nil {
		m.current.serverCA = m.newServerCA(x509util.NewMemoryKeypair(m.current.x509Cert, m.current.x509Key))
	}
}

func (*MemoryPlugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (m *MemoryPlugin) SignX509SvidCsr(ctx context.Context, request *ca.SignX509SvidCsrRequest) (*ca.SignX509SvidCsrResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.current == nil {
		return nil, errors.New("invalid state: no certificate loaded")
	}

	cert, err := m.current.serverCA.SignCSR(ctx, request.Csr, time.Duration(request.Ttl)*time.Second)
	if err != nil {
		return nil, err
	}

	return &ca.SignX509SvidCsrResponse{SignedCertificate: cert.Raw}, nil
}

func (m *MemoryPlugin) SignJwtSvid(ctx context.Context, request *ca.SignJwtSvidRequest) (*ca.SignJwtSvidResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	switch {
	case m.current == nil:
		return nil, errors.New("Invalid state: no certificate")
	case request.SpiffeId == "":
		return nil, errors.New("Invalid request: SPIFFE ID is required")
	case len(request.Audience) == 0:
		return nil, errors.New("Invalid request: at least one audience is required")
	case request.Ttl < 0:
		return nil, errors.New("Invalid request: TTL is invalid")
	}

	if request.Ttl == 0 {
		request.Ttl = int32(m.config.DefaultTTL)
	}
	ttl := time.Duration(request.Ttl) * time.Second
	if ttl == 0 {
		ttl = x509svid.DefaultServerCATTL
	}

	token, err := jwtsvid.SignSimpleToken(
		request.SpiffeId, request.Audience,
		m.hooks.now().Add(ttl),
		m.current.jwtKey, m.current.jwtCert)
	if err != nil {
		return nil, fmt.Errorf("unable to build JWT-SVID: %v", err)
	}

	return &ca.SignJwtSvidResponse{
		SignedJwt: token,
	}, nil
}

func (m *MemoryPlugin) GenerateCsr(ctx context.Context, req *ca.GenerateCsrRequest) (*ca.GenerateCsrResponse, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	x509Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Can't generate X509-SVID CA private key: %v", err)
	}

	csr, err := x509svid.GenerateServerCACSR(x509Key, m.config.TrustDomain,
		x509svid.ServerCACSROptions{
			Subject: pkix.Name{
				Country:      m.config.CertSubject.Country,
				Organization: m.config.CertSubject.Organization,
				CommonName:   m.config.CertSubject.CommonName,
			},
		})

	m.next = &keypairs{
		x509Key: x509Key,
	}
	return &ca.GenerateCsrResponse{Csr: csr}, nil
}

func (m *MemoryPlugin) LoadCertificate(ctx context.Context, request *ca.LoadCertificateRequest) (response *ca.LoadCertificateResponse, err error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.next == nil {
		return nil, errors.New("invalid state: no private key")
	}

	cert, err := x509svid.ParseAndValidateServerCACertificate(request.SignedIntermediateCert, m.config.TrustDomain)
	if err != nil {
		return nil, err
	}

	keypair := x509util.NewMemoryKeypair(cert, m.next.x509Key)

	jwtCert, jwtKey, err := m.generateJWTKeypair(ctx, cert, keypair)
	if err != nil {
		return nil, err
	}

	m.next.x509Cert = cert
	m.next.serverCA = m.newServerCA(keypair)
	m.next.jwtCert = jwtCert
	m.next.jwtKey = jwtKey

	// swap in the new keypairs
	m.current, m.next = m.next, nil

	return &ca.LoadCertificateResponse{}, nil
}

// getX509SVIDCertificate returns the X509-SVID signing certificate.
func (m *MemoryPlugin) getX509SVIDCertificate() (*x509.Certificate, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.current == nil {
		return nil, errors.New("no certificate loaded")
	}

	return m.current.x509Cert, nil
}

// getJWTASVIDCertificate returns the JWT-A-SVID signing certificate.
func (m *MemoryPlugin) getJWTASVIDCertificate() (*x509.Certificate, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.current == nil {
		return nil, errors.New("no certificate loaded")
	}

	return m.current.jwtCert, nil
}

func (m *MemoryPlugin) generateJWTKeypair(ctx context.Context, parentCert *x509.Certificate, keypair x509util.Keypair) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	jwtKey, err := jwtsvid.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create JWT key: %v", err)
	}

	serialNumber, err := m.serialNumber.NextNumber(ctx)
	if err != nil {
		return nil, nil, err
	}

	template := jwtsvid.CreateCertificateTemplate(parentCert)
	template.SerialNumber = serialNumber

	certBytes, err := keypair.CreateCertificate(ctx, template, &jwtKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create JWT cert: %v", err)
	}

	jwtCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return jwtCert, jwtKey, nil
}

func (m *MemoryPlugin) newServerCA(keypair x509util.Keypair) *x509svid.ServerCA {
	return x509svid.NewServerCA(keypair,
		m.config.TrustDomain,
		x509svid.ServerCAOptions{
			TTL:          time.Duration(m.config.DefaultTTL) * time.Second,
			Backdate:     time.Duration(m.config.BackdateSecs) * time.Second,
			SerialNumber: m.serialNumber,
		})
}
