package pkg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"fmt"
	"github.com/spiffe/go-spiffe"
	"github.com/spiffe/sri/pkg/common/plugin"
	common "github.com/spiffe/sri/pkg/common/plugin"
	iface "github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/server/upstreamca"
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

type configuration struct {
	TTL         time.Duration `json:"ttl"` // time to live for generated certs
	TrustDomain string        `json:"trust_domain"`
	KeySize     int           `json:"key_size"`
	CertSubject pkix.Name     `json:"cert_subject"`
}

type memoryPlugin struct {
	config *configuration

	key    *rsa.PrivateKey
	cert   *x509.Certificate
	serial int64

	mtx *sync.RWMutex
}

func (m *memoryPlugin) Configure(req *common.ConfigureRequest) (*common.ConfigureResponse, error) {
	// Parse JSON config payload into config struct
	config := &configuration{}
	if err := json.Unmarshal([]byte(req.Configuration), &config); err != nil {
		resp := &common.ConfigureResponse{
			ErrorList: []string{err.Error()},
		}
		return resp, err
	}

	key, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, errors.New("Can't generate private key: " + err.Error())
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      config.CertSubject,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	der, err := x509.CreateCertificate(rand.Reader,
		template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	// Set local vars from config struct
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.config = &configuration{}
	m.config.TrustDomain = config.TrustDomain
	m.config.TTL = config.TTL
	m.config.KeySize = config.KeySize
	m.config.CertSubject = config.CertSubject
	m.cert = cert
	m.key = key

	return &common.ConfigureResponse{}, nil
}

func (memoryPlugin) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

func (m *memoryPlugin) SubmitCSR(csrPEM []byte) (*upstreamca.SubmitCSRResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.cert == nil {
		return nil, errors.New("Invalid state: no cert")
	}

	if m.key == nil {
		return nil, errors.New("Invalid state: no key")
	}

	csr, err := ParseSpiffeCsr(csrPEM, m.config.TrustDomain)

	if err != nil {
		return nil, err
	}

	serial := atomic.AddInt64(&m.serial, 1)
	now := time.Now()

	template := x509.Certificate{
		ExtraExtensions: csr.Extensions,
		Subject:         csr.Subject,
		Issuer:          m.cert.Subject,
		SerialNumber:    big.NewInt(serial),
		NotBefore:       now,
		NotAfter:        now.Add(m.config.TTL),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader,
		&template, m.cert, &m.key.PublicKey, m.key)

	if err != nil {
		return nil, err
	}

	return &upstreamca.SubmitCSRResponse{
		Cert: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}),
		UpstreamTrustBundle: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: m.cert.Raw,
		}),
	}, nil
}

func ParseSpiffeCsr(csrPEM []byte, trustDomain string) (csr *x509.CertificateRequest, err error) {
	block, rest := pem.Decode(csrPEM)
	if len(rest) > 0 {
		return nil, errors.New("Invalid CSR format")
	}

	csr, err = x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	err = csr.CheckSignature()
	if err != nil {
		return nil, errors.New("Failed to check certificate request signature: " + err.Error())
	}

	urinames, err := spiffe.GetURINamesFromExtensions(&csr.Extensions)
	if err != nil {
		return nil, err
	}

	if len(urinames) != 1 {
		return nil, errors.New("The CSR must have exactly one URI SAN")
	}

	csrSpiffeID, err := url.Parse(urinames[0])

	if csrSpiffeID.Scheme != "spiffe" {
		return nil, errors.New("SPIFFE IDs must be prefixed with the spiffe:// scheme.")
	}

	if csrSpiffeID.Host != trustDomain {
		return nil, fmt.Errorf("The SPIFFE ID '%v' does not reside in the trust domain '%v'.", urinames[0], trustDomain)
	}

	return csr, nil
}

func NewWithDefault() (m upstreamca.UpstreamCa, err error) {
	config := `{"trust_domain":"localhost", "ttl":3600000, "key_size":2048}`
	pluginConfig := &iface.ConfigureRequest{
		Configuration: config,
	}

	m = &memoryPlugin{
		mtx: &sync.RWMutex{},
	}

	_, err = m.Configure(pluginConfig)

	return m, err
}
