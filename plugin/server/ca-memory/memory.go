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
	"github.com/spiffe/go-spiffe"
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

type configuration struct {
	TrustDomain string        `json:"trust_domain"`
	KeySize     int           `json:"key_size"`
	TTL         time.Duration `json:"ttl"`
	CertSubject pkix.Name     `json:"cert_subject"`
}

type memoryPlugin struct {
	config *configuration

	key    *rsa.PrivateKey
	cert   *x509.Certificate
	serial int64

	mtx *sync.RWMutex
}

func (m *memoryPlugin) Configure(req *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error) {
	// Parse JSON config payload into config struct
	config := &configuration{}
	if err := json.Unmarshal([]byte(req.Configuration), &config); err != nil {
		resp := &sriplugin.ConfigureResponse{
			ErrorList: []string{err.Error()},
		}
		return resp, err
	}

	key, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, errors.New("Can't generate private key: " + err.Error())
	}

	// Set local vars from config struct
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.config = &configuration{}
	m.config.TrustDomain = config.TrustDomain
	m.config.TTL = config.TTL
	m.config.KeySize = config.KeySize
	m.config.CertSubject = config.CertSubject
	m.key = key

	return &sriplugin.ConfigureResponse{}, nil
}

func (memoryPlugin) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

func (m memoryPlugin) SignCsr(csrPEM []byte) ([]byte, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.cert == nil {
		return nil, errors.New("Invalid state: no certificate")
	}

	csr, err := pkg.ParseSpiffeCsr(csrPEM, m.config.TrustDomain)
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
		NotBefore:       now,
		NotAfter:        now.Add(m.config.TTL),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader,
		&template, m.cert, &m.key.PublicKey, m.key)

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}), nil
}

func (m *memoryPlugin) GenerateCsr() ([]byte, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.key == nil {
		return nil, errors.New("Invalid state: no private key")
	}

	uriSans, err := spiffe.MarshalUriSANs([]string{fmt.Sprintf("spiffe://%v", m.config.TrustDomain)})
	if err != nil {
		return nil, err
	}

	template := x509.CertificateRequest{
		Subject:            m.config.CertSubject,
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       spiffe.OidExtensionSubjectAltName,
				Value:    uriSans,
				Critical: true,
			}},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, m.key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}), nil
}

func (m memoryPlugin) FetchCertificate() ([]byte, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.cert == nil {
		// return empty result if uninitialized.
		return nil, nil
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: m.cert.Raw,
	}), nil
}

func (m *memoryPlugin) LoadCertificate(certPEM []byte) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.key == nil {
		return errors.New("Invalid state: no private key")
	}

	block, rest := pem.Decode(certPEM)

	if block == nil {
		return errors.New("Invalid cert format")
	}

	if len(rest) > 0 {
		return errors.New("Invalid cert format: too many certs")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	uris, err := spiffe.GetURINamesFromCertificate(cert)
	if err != nil {
		return err
	}

	if len(uris) != 1 {
		return fmt.Errorf("X.509 SVID certificates must have exactly one URI SAN. Found %v URI(s)", len(uris))
	}

	keyUsageExtensions := spiffe.GetKeyUsageExtensionsFromCertificate(cert)

	if keyUsageExtensions == nil {
		return errors.New("The Key Usage extension must be set on X.509 SVID certificates")
	}

	if !keyUsageExtensions[0].Critical {
		return errors.New("The Key Usage extension must be marked critical on X.509 SVID certificates")
	}

	spiffeidUrl, err := url.Parse(uris[0])

	if spiffeidUrl.Scheme != "spiffe" {
		return errors.New("SPIFFE IDs in X.509 SVID certificates must be prefixed with the spiffe:// scheme.")
	}

	if spiffeidUrl.Host != m.config.TrustDomain {
		return fmt.Errorf("The SPIFFE ID '%v' does not reside in the trust domain '%v'.", spiffeidUrl, m.config.TrustDomain)
	}

	if cert.MaxPathLen > 0 || (cert.MaxPathLen == 0 && cert.MaxPathLenZero) {
		return errors.New("Signing certificates must not set the pathLenConstraint field")
	}

	if !cert.IsCA {
		return errors.New("Signing certificates must set the CA field to true")
	}

	if len(spiffeidUrl.Path) > 0 {
		return errors.New("Signing certificates must not have a path component")
	}

	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("Signing certificates must set KeyUsageCertSign")
	}

	if cert.KeyUsage&x509.KeyUsageKeyEncipherment > 0 {
		return errors.New("Signing certificates must not set KeyUsageKeyEncipherment")
	}

	if cert.KeyUsage&x509.KeyUsageKeyAgreement > 0 {
		return errors.New("Signing certificates must not set KeyUsageKeyAgreement")
	}

	m.cert = cert
	return nil
}

func NewWithDefault() (m ca.ControlPlaneCa, err error) {
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
