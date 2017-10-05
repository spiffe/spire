package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/uri"

	"github.com/spiffe/spire/plugin/server/upstreamca-memory/pkg"
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
	TrustDomain string            `hcl:"trust_domain" json:"trust_domain"`
	KeySize     int               `hcl:"key_size" json:"key_size"`
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

func (m *memoryPlugin) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	log.Print("Starting Configure")

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

	// Set local vars from config struct
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.config = &configuration{}
	m.config.TrustDomain = config.TrustDomain
	m.config.KeySize = config.KeySize
	m.config.CertSubject = config.CertSubject

	return resp, nil
}

func (*memoryPlugin) GetPluginInfo(req *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	log.Print("Getting plugin information")

	return &spi.GetPluginInfoResponse{}, nil
}

func (m *memoryPlugin) SignCsr(request *ca.SignCsrRequest) (*ca.SignCsrResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	log.Print("Starting SignCsr")
	if m.cert == nil {
		return nil, errors.New("Invalid state: no certificate")
	}

	if request.Ttl == 0 {
		log.Printf("TTL is set to 0. Using default TTL: %v", defaultTTL)
		request.Ttl = defaultTTL
	} else if request.Ttl < 0 {
		return nil, fmt.Errorf("Invalid TTL: %v", request.Ttl)
	}

	csr, err := pkg.ParseSpiffeCsr(request.Csr, m.config.TrustDomain)
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
		NotBefore:       now.Add(time.Duration(-10) * time.Second),
		NotAfter:        now.Add(time.Duration(request.Ttl) * time.Second),
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

	log.Print("Certificate successfully created")
	return &ca.SignCsrResponse{SignedCertificate: signedCertificate}, nil
}

func (m *memoryPlugin) GenerateCsr(*ca.GenerateCsrRequest) (*ca.GenerateCsrResponse, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	log.Print("Starting generation of CSR")

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
				Id:       uri.OidExtensionSubjectAltName,
				Value:    uriSans,
				Critical: false,
			}},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, m.newKey)
	if err != nil {
		return nil, err
	}

	log.Printf("CSR with SPIFFE ID: '%v' successfully generated", spiffeID.String())
	return &ca.GenerateCsrResponse{Csr: csr}, nil
}

func (m *memoryPlugin) FetchCertificate(request *ca.FetchCertificateRequest) (*ca.FetchCertificateResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	log.Print("Starting fetching signing certificate")

	if m.cert == nil {
		// return empty result if uninitialized.
		log.Print("No certificate to fetch")
		return &ca.FetchCertificateResponse{}, nil
	}

	certUris, err := uri.GetURINamesFromCertificate(m.cert)
	if err != nil && len(certUris) > 0 {
		log.Printf("Certificate with SPIFFE ID: '%v' found", certUris[0])
	} else {
		log.Print("The signing certificate loaded does not have a SPIFFE ID!")
	}

	return &ca.FetchCertificateResponse{StoredIntermediateCert: m.cert.Raw}, nil
}

func (m *memoryPlugin) LoadCertificate(request *ca.LoadCertificateRequest) (response *ca.LoadCertificateResponse, err error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	log.Print("Loading signing certificate")
	if m.newKey == nil {
		return &ca.LoadCertificateResponse{}, errors.New("Invalid state: no private key. GenerateCsr() should be called first")
	}

	m.key = m.newKey

	cert, err := x509.ParseCertificate(request.SignedIntermediateCert)
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

	keyUsageExtensions := uri.GetKeyUsageExtensionsFromCertificate(cert)

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

	log.Printf("Signing certificate with SPIFFE ID: '%v' successfully loaded", spiffeidUrl.String())

	return &ca.LoadCertificateResponse{}, nil
}

func NewWithDefault() (m ca.ControlPlaneCa, err error) {
	config := configuration{
		TrustDomain: "localhost",
		KeySize:     2048,
		CertSubject: certSubjectConfig{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "",
		}}

	jsonConfig, err := json.Marshal(config)

	if err != nil {
		return nil, err
	}

	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
	}

	m = &memoryPlugin{
		mtx: &sync.RWMutex{},
	}

	_, err = m.Configure(pluginConfig)

	return m, err
}

func main() {
	log.Print("Starting plugin")

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
