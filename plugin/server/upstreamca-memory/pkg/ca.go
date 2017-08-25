package pkg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/server/upstreamca"
)

const (
	defaultKeySize = 1024 // small for testing
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
	TTL time.Duration // time to live for generated certs

	KeySize     int
	CertSubject pkix.Name
}

type memoryPlugin struct {
	config *configuration

	key    *rsa.PrivateKey
	cert   *x509.Certificate
	serial int64

	mtx *sync.RWMutex
}

func (m *memoryPlugin) Configure(rawConfig string) ([]string, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// TODO: parse, apply config

	return nil, errors.New("Not Implemented")
}

func (memoryPlugin) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

func (m *memoryPlugin) SubmitCSR(csrPEM []byte) (*upstreamca.SubmitCSRResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.cert == nil || m.key == nil {
		return nil, errors.New("invalid state: no cert or key")
	}

	block, rest := pem.Decode(csrPEM)
	if len(rest) > 0 {
		return nil, errors.New("Invalid CSR Format")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	// TODO: validate CSR

	serial := atomic.AddInt64(&m.serial, 1)
	now := time.Now()

	// TODO: proper SPIFFE cert fields
	template := x509.Certificate{
		Subject:      csr.Subject,
		Issuer:       m.cert.Subject,
		SerialNumber: big.NewInt(serial),
		NotBefore:    now,
		NotAfter:     now.Add(m.config.TTL),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

func NewWithDefault() (upstreamca.UpstreamCa, error) {
	m := &memoryPlugin{
		mtx: &sync.RWMutex{},
	}
	return m, m.applyConfig(defaultConfig())
}

func (m *memoryPlugin) applyConfig(config *configuration) error {

	key, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return errors.New("Can't generate private key: " + err.Error())
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	// TODO: proper SPIFFE cert fields
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      config.CertSubject,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}

	der, err := x509.CreateCertificate(rand.Reader,
		template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}

	m.key = key
	m.cert = cert
	m.config = config
	return nil
}

func defaultConfig() *configuration {
	return &configuration{
		TTL:     time.Hour * 24 * 30,
		KeySize: defaultKeySize,
		CertSubject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "",
		},
	}
}
