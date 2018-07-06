package memory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/uri"

	"github.com/spiffe/spire/pkg/server/plugin/upstreamca/disk"
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

const defaultTTL = 3600 // One hour

type certSubjectConfig struct {
	Country      []string
	Organization []string
	CommonName   string
}

type configuration struct {
	TrustDomain  string            `hcl:"trust_domain" json:"trust_domain"`
	BackdateSecs int               `hcl:"backdate_seconds" json:"backdate_seconds"`
	KeySize      int               `hcl:"key_size" json:"key_size"`
	CertSubject  certSubjectConfig `hcl:"cert_subject" json:"cert_subject"`
	DefaultTTL   int               `hcl:"default_ttl" json:"default_ttl"`
}

type MemoryPlugin struct {
	config *configuration

	key    *ecdsa.PrivateKey
	newKey *ecdsa.PrivateKey
	cert   *x509.Certificate
	serial int64

	mtx *sync.RWMutex
}

func (m *MemoryPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	resp := &spi.ConfigureResponse{}

	// Parse HCL config payload into config struct
	config := &configuration{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

	ttl := defaultTTL
	if config.DefaultTTL > 0 {
		ttl = config.DefaultTTL
	}

	// Set local vars from config struct
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.config = &configuration{}
	m.config.TrustDomain = config.TrustDomain
	m.config.BackdateSecs = config.BackdateSecs
	m.config.KeySize = config.KeySize
	m.config.CertSubject = config.CertSubject
	m.config.DefaultTTL = ttl

	return resp, nil
}

func (*MemoryPlugin) GetPluginInfo(ctx context.Context, req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (m *MemoryPlugin) SignCsr(ctx context.Context, request *ca.SignCsrRequest) (*ca.SignCsrResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.cert == nil {
		return nil, errors.New("invalid state: no certificate")
	}

	csr, err := disk.ParseSpiffeCsr(request.Csr, m.config.TrustDomain)
	if err != nil {
		return nil, err
	}

	serial := atomic.AddInt64(&m.serial, 1)
	now := time.Now()

	template := x509.Certificate{
		ExtraExtensions: csr.Extensions,
		Subject:         csr.Subject,
		Issuer:          csr.Subject,
		SerialNumber:    big.NewInt(serial),
		NotBefore:       now.Add(time.Duration(-m.config.BackdateSecs) * time.Second),
		NotAfter:        m.safeExpiry(request.Ttl),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	signedCertificate, err := x509.CreateCertificate(rand.Reader,
		&template, m.cert, csr.PublicKey, m.key)

	if err != nil {
		return nil, err
	}

	return &ca.SignCsrResponse{SignedCertificate: signedCertificate}, nil
}

func (m *MemoryPlugin) GenerateCsr(ctx context.Context, req *ca.GenerateCsrRequest) (*ca.GenerateCsrResponse, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	newKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, errors.New("generate private key: " + err.Error())
	}
	m.newKey = newKey

	spiffeID := url.URL{
		Scheme: "spiffe",
		Host:   m.config.TrustDomain,
	}

	uriSans, err := uri.MarshalUriSANs([]string{spiffeID.String()})
	if err != nil {
		return nil, err
	}

	subject := pkix.Name{
		Country:      m.config.CertSubject.Country,
		Organization: m.config.CertSubject.Organization,
		CommonName:   m.config.CertSubject.CommonName,
	}

	template := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       uri.OidExtensionSubjectAltName,
				Value:    uriSans,
				Critical: false,
			}},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, m.newKey)
	if err != nil {
		return nil, err
	}

	return &ca.GenerateCsrResponse{Csr: csr}, nil
}

func (m *MemoryPlugin) FetchCertificate(ctx context.Context, request *ca.FetchCertificateRequest) (*ca.FetchCertificateResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.cert == nil {
		// return empty result if uninitialized.
		return &ca.FetchCertificateResponse{}, nil
	}

	return &ca.FetchCertificateResponse{StoredIntermediateCert: m.cert.Raw}, nil
}

func (m *MemoryPlugin) LoadCertificate(ctx context.Context, request *ca.LoadCertificateRequest) (response *ca.LoadCertificateResponse, err error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.newKey == nil {
		return &ca.LoadCertificateResponse{}, errors.New("invalid state: no private key")
	}

	cert, err := x509.ParseCertificate(request.SignedIntermediateCert)
	if err != nil {
		return &ca.LoadCertificateResponse{}, err
	}

	uris, err := uri.GetURINamesFromCertificate(cert)
	if err != nil {
		return &ca.LoadCertificateResponse{}, err
	}

	if len(uris) != 1 {
		return &ca.LoadCertificateResponse{}, fmt.Errorf("load certificate: found %v URI(s); must have exactly one", len(uris))
	}

	keyUsageExtensions := uri.GetKeyUsageExtensionsFromCertificate(cert)

	if len(keyUsageExtensions) == 0 {
		return &ca.LoadCertificateResponse{}, errors.New("load certificate: key usage extension must be set")
	}

	if !keyUsageExtensions[0].Critical {
		return &ca.LoadCertificateResponse{}, errors.New("load certificate: key usage extension must be marked critical")
	}

	spiffeidUrl, err := url.Parse(uris[0])

	if spiffeidUrl.Scheme != "spiffe" {
		return &ca.LoadCertificateResponse{}, errors.New("load certificate: missing spiffe:// scheme")
	}

	if spiffeidUrl.Host != m.config.TrustDomain {
		return &ca.LoadCertificateResponse{}, fmt.Errorf("load certificate: wrong trust domain (want %v ; got %v)", spiffeidUrl.Host, m.config.TrustDomain)
	}

	if cert.MaxPathLen > 0 || (cert.MaxPathLen == 0 && cert.MaxPathLenZero) {
		return &ca.LoadCertificateResponse{}, errors.New("load certificae: pathLenConstraint must not be set")
	}

	if !cert.IsCA {
		return &ca.LoadCertificateResponse{}, errors.New("load certificate: not a CA cert")
	}

	if len(spiffeidUrl.Path) > 0 {
		return &ca.LoadCertificateResponse{}, errors.New("load certificate: SPIFFE ID must not have a path component")
	}

	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return &ca.LoadCertificateResponse{}, errors.New("load certificate: KeyUsageCertSign must be set")
	}

	if cert.KeyUsage&x509.KeyUsageKeyEncipherment > 0 {
		return &ca.LoadCertificateResponse{}, errors.New("load certificate: KeyUsageKeyEncipherment must not be set")
	}

	if cert.KeyUsage&x509.KeyUsageKeyAgreement > 0 {
		return &ca.LoadCertificateResponse{}, errors.New("load certificate: KeyUsageKeyAgreement must not be set")
	}

	m.cert = cert
	m.key = m.newKey

	return &ca.LoadCertificateResponse{}, nil
}

func (m *MemoryPlugin) safeExpiry(ttl int32) time.Time {
	if ttl == 0 {
		ttl = int32(m.config.DefaultTTL)
	}

	requestedExpiry := time.Now().Add(time.Duration(ttl) * time.Second)
	if requestedExpiry.After(m.cert.NotAfter) {
		return m.cert.NotAfter
	}

	return requestedExpiry
}

func NewWithDefault() ca.Plugin {
	config := configuration{
		TrustDomain:  "localhost",
		BackdateSecs: 10,
		KeySize:      2048,
		CertSubject: certSubjectConfig{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "",
		}}

	// Safe to ignore error here since we control the input
	jsonConfig, _ := json.Marshal(config)

	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
	}

	m := &MemoryPlugin{
		mtx: &sync.RWMutex{},
	}

	// TODO: currently NewWithDefault is called during package init time where
	// a context isn't available...
	m.Configure(context.TODO(), pluginConfig)

	return m
}
