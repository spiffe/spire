package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl"

	"github.com/spiffe/go-spiffe/spiffe"
	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/sri/pkg/common/plugin"
	iface "github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/server/ca"
	"github.com/spiffe/sri/plugin/server/upstreamca-memory/pkg"
)

var (
	pluginInfo = sriplugin.GetPluginInfoResponse{
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
	TrustDomain string            `hcl:"trust_domain" json:"trust_domain"`
	KeySize     int               `hcl:"key_size" json:"key_size"`
	TTL         string            `hcl:"ttl" json:"ttl"`
	CertSubject certSubjectConfig `hcl:"cert_subject" json:"cert_subject"`
}

type memoryPlugin struct {
	config *configuration

	key    *rsa.PrivateKey
	newKey *rsa.PrivateKey
	cert   *x509.Certificate
	serial int64

	mtx *sync.RWMutex
}

func (m *memoryPlugin) Configure(req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	resp := &sriplugin.ConfigureResponse{}

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

	// Set local vars from config struct
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.config = &configuration{}
	m.config.TrustDomain = config.TrustDomain
	m.config.TTL = config.TTL
	m.config.KeySize = config.KeySize
	m.config.CertSubject = config.CertSubject

	return resp, nil
}

func (*memoryPlugin) GetPluginInfo(req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	return &sriplugin.GetPluginInfoResponse{}, nil
}

func (m *memoryPlugin) SignCsr(request *ca.SignCsrRequest) (*ca.SignCsrResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.cert == nil {
		return nil, errors.New("Invalid state: no certificate")
	}

	csr, err := pkg.ParseSpiffeCsr(request.Csr, m.config.TrustDomain)
	if err != nil {
		return nil, err
	}

	serial := atomic.AddInt64(&m.serial, 1)
	now := time.Now()

	expiry, err := time.ParseDuration(m.config.TTL)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse TTL: %s", err)
	}

	template := x509.Certificate{
		ExtraExtensions: csr.Extensions,
		Subject:         csr.Subject,
		Issuer:          csr.Subject,
		SerialNumber:    big.NewInt(serial),
		NotBefore:       now,
		NotAfter:        now.Add(expiry),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader,
		&template, m.cert, csr.PublicKey, m.key)

	if err != nil {
		return nil, err
	}

	return &ca.SignCsrResponse{SignedCertificate: pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})}, nil
}

func (m *memoryPlugin) GenerateCsr(*ca.GenerateCsrRequest) (*ca.GenerateCsrResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	newKey, err := rsa.GenerateKey(rand.Reader, m.config.KeySize)
	if err != nil {
		return nil, errors.New("Can't generate private key: " + err.Error())
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
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       spiffe.OidExtensionSubjectAltName,
				Value:    uriSans,
				Critical: false,
			}},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, m.newKey)
	if err != nil {
		return nil, err
	}

	return &ca.GenerateCsrResponse{Csr: pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})}, nil
}

func (m *memoryPlugin) FetchCertificate(request *ca.FetchCertificateRequest) (*ca.FetchCertificateResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.cert == nil {
		// return empty result if uninitialized.
		return &ca.FetchCertificateResponse{}, nil
	}

	return &ca.FetchCertificateResponse{StoredIntermediateCert: pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: m.cert.Raw,
	})}, nil
}

func (m *memoryPlugin) LoadCertificate(request *ca.LoadCertificateRequest) (response *ca.LoadCertificateResponse, err error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.newKey == nil {
		return &ca.LoadCertificateResponse{}, errors.New("Invalid state: no private key. GenerateCsr() should be called first")
	}

	m.key = m.newKey

	block, rest := pem.Decode(request.SignedIntermediateCert)

	if block == nil {
		return &ca.LoadCertificateResponse{}, errors.New("Invalid cert format")
	}

	if len(rest) > 0 {
		return &ca.LoadCertificateResponse{}, errors.New("Invalid cert format: too many certs")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &ca.LoadCertificateResponse{}, err
	}

	uris, err := uri.GetURINamesFromCertificate(cert)
	if err != nil {
		return &ca.LoadCertificateResponse{}, err
	}

	if len(uris) != 1 {
		return &ca.LoadCertificateResponse{}, fmt.Errorf("X.509 SVID certificates must have exactly one URI SAN. Found %v URI(s)", len(uris))
	}

	keyUsageExtensions := spiffe.GetKeyUsageExtensionsFromCertificate(cert)

	if len(keyUsageExtensions) == 0 {
		return &ca.LoadCertificateResponse{}, errors.New("The Key Usage extension must be set on X.509 SVID certificates")
	}

	if !keyUsageExtensions[0].Critical {
		return &ca.LoadCertificateResponse{}, errors.New("The Key Usage extension must be marked critical on X.509 SVID certificates")
	}

	spiffeidUrl, err := url.Parse(uris[0])

	if spiffeidUrl.Scheme != "spiffe" {
		return &ca.LoadCertificateResponse{}, errors.New("SPIFFE IDs in X.509 SVID certificates must be prefixed with the spiffe:// scheme.")
	}

	if spiffeidUrl.Host != m.config.TrustDomain {
		return &ca.LoadCertificateResponse{}, fmt.Errorf("The SPIFFE ID '%v' does not reside in the trust domain '%v'.", spiffeidUrl, m.config.TrustDomain)
	}

	if cert.MaxPathLen > 0 || (cert.MaxPathLen == 0 && cert.MaxPathLenZero) {
		return &ca.LoadCertificateResponse{}, errors.New("Signing certificates must not set the pathLenConstraint field")
	}

	if !cert.IsCA {
		return &ca.LoadCertificateResponse{}, errors.New("Signing certificates must set the CA field to true")
	}

	if len(spiffeidUrl.Path) > 0 {
		return &ca.LoadCertificateResponse{}, errors.New("Signing certificates must not have a path component")
	}

	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return &ca.LoadCertificateResponse{}, errors.New("Signing certificates must set KeyUsageCertSign")
	}

	if cert.KeyUsage&x509.KeyUsageKeyEncipherment > 0 {
		return &ca.LoadCertificateResponse{}, errors.New("Signing certificates must not set KeyUsageKeyEncipherment")
	}

	if cert.KeyUsage&x509.KeyUsageKeyAgreement > 0 {
		return &ca.LoadCertificateResponse{}, errors.New("Signing certificates must not set KeyUsageKeyAgreement")
	}

	m.cert = cert
	return &ca.LoadCertificateResponse{}, nil
}

func NewWithDefault() (m ca.ControlPlaneCa, err error) {
	config := configuration{
		TrustDomain: "localhost",
		KeySize:     2048,
		TTL:         "1h",
		CertSubject: certSubjectConfig{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "",
		}}

	jsonConfig, err := json.Marshal(config)

	if err != nil {
		return nil, err
	}

	pluginConfig := &iface.ConfigureRequest{
		Configuration: string(jsonConfig),
	}

	m = &memoryPlugin{
		mtx: &sync.RWMutex{},
	}

	_, err = m.Configure(pluginConfig)

	return m, err
}

func main() {
	cax, err := NewWithDefault()
	if err != nil {
		panic(err.Error())
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: ca.Handshake,
		Plugins: map[string]plugin.Plugin{
			"ca": ca.ControlPlaneCaPlugin{
				ControlPlaneCaImpl: cax,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
