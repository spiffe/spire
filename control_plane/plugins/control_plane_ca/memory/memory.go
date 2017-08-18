package main

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

	"github.com/hashicorp/go-plugin"
	common "github.com/spiffe/sri/common/plugins/common/proto"
	"github.com/spiffe/sri/control_plane/plugins/control_plane_ca"
)

const (
	defaultKeySize = 1024 // small for testing
)

var (
	pluginInfo = common.GetPluginInfoResponse{
		Description: "",
		DateCreated: "",
		Version:     "",
		Author:      "",
		Company:     "",
	}
)

type configuration struct {
	KeySize int
	TTL     time.Duration

	CertSubject pkix.Name
}

type memoryPlugin struct {
	config *configuration

	key    *rsa.PrivateKey
	cert   *x509.Certificate
	serial int64

	mtx *sync.RWMutex
}

// TODO: what to return?
func (m *memoryPlugin) Configure(rawConfig string) ([]string, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// TODO: parse, apply configuration

	return nil, errors.New("Not Implemented")
}

func (memoryPlugin) GetPluginInfo() (*common.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

func (m memoryPlugin) SignCsr(csrPEM []byte) ([]byte, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	if m.cert == nil {
		return nil, errors.New("invalid state: no certificate")
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
		return nil, errors.New("invalid state: no private key")
	}

	// TODO: proper SPIFFE cert fields
	template := x509.CertificateRequest{
		Subject:            m.config.CertSubject,
		SignatureAlgorithm: x509.SHA256WithRSA,
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
		return errors.New("invalid state: no private key")
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

	if !cert.IsCA {
		return errors.New("Invalid cert format: not CA")
	}

	// TODO: validate cert

	m.cert = cert
	return nil
}

func NewWithDefault() (controlplaneca.ControlPlaneCa, error) {
	config := defaultConfig()
	key, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, errors.New("Can't generate private key: " + err.Error())
	}
	return NewWithConfig(config, key)
}

func NewWithConfig(config *configuration, key *rsa.PrivateKey) (controlplaneca.ControlPlaneCa, error) {
	return &memoryPlugin{
		key:    key,
		mtx:    &sync.RWMutex{},
		config: config,
	}, nil
}

func defaultConfig() *configuration {
	return &configuration{
		KeySize: defaultKeySize,
		TTL:     time.Hour,
		CertSubject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "",
		},
	}
}

func (m *memoryPlugin) applyConfig(config *configuration) error {
	key, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return errors.New("Can't generate private key: " + err.Error())
	}
	m.key = key
	m.config = config
	m.cert = nil
	return nil
}

func main() {
	ca, err := NewWithDefault()
	if err != nil {
		panic(err.Error())
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: controlplaneca.Handshake,
		Plugins: map[string]plugin.Plugin{
			"controlplaneca": controlplaneca.ControlPlaneCaPlugin{
				ControlPlaneCaImpl: ca,
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
