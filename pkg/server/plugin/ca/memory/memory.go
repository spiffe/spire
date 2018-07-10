package memory

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
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
	KeypairPath  string            `hcl:"keypair_path" json:"keypair_path"`
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
	}, nil)
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

	var keypair *x509util.MemoryKeypair
	if config.KeypairPath != "" {
		cert, key, err := loadKeypair(config.KeypairPath)
		switch {
		case err == nil:
			keypair = x509util.NewMemoryKeypair(cert, key)
		case os.IsNotExist(err):
		default:
			return nil, err
		}
	}

	m.configure(config, keypair)
	return &spi.ConfigureResponse{}, nil
}

func (m *MemoryPlugin) configure(config *configuration, keypair *x509util.MemoryKeypair) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.keypair = keypair
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

	keypair := x509util.NewMemoryKeypair(cert, m.newKey)
	if m.config.KeypairPath != "" {
		if err := writeKeypair(m.config.KeypairPath, cert, m.newKey); err != nil {
			return nil, err
		}
	}

	m.keypair = keypair
	m.initializeCA()

	return &ca.LoadCertificateResponse{}, nil
}

func loadKeypair(path string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	// parse certificate
	certBlock, pemBytes := pem.Decode(pemBytes)
	if certBlock == nil {
		return nil, nil, errors.New("missing CERTIFICATE block")
	}
	if certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("expected first block to be CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse certificate: %v", err)
	}

	// parse key
	keyBlock, _ := pem.Decode(pemBytes)
	if keyBlock == nil {
		return nil, nil, errors.New("missing PRIVATE KEY block")
	}
	if keyBlock.Type != "PRIVATE KEY" {
		return nil, nil, errors.New("expected second block to be PRIVATE KEY")
	}
	rawKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("expecting ECDSA private key; got %T", rawKey)
	}

	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("expected certificate to ECDSA public key; got %T", cert.PublicKey)
	}

	// make sure keys match
	if !(key.X.Cmp(publicKey.X) == 0 && key.Y.Cmp(publicKey.Y) == 0) {
		return nil, nil, errors.New("certificate and key do not match")
	}

	return cert, key, nil
}

func writeKeypair(path string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("unable to marshal private key: %v", err)
	}

	buffer := new(bytes.Buffer)
	if err := pem.Encode(buffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}); err != nil {
		return fmt.Errorf("unable to encode certificate: %v", err)
	}

	if err := pem.Encode(buffer, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		return fmt.Errorf("unable to encode private key: %v", err)
	}

	if err := ioutil.WriteFile(path+".tmp", buffer.Bytes(), 0600); err != nil {
		return fmt.Errorf("unable to write temporary keypair: %v", err)
	}

	if err := os.Rename(path+".tmp", path); err != nil {
		return fmt.Errorf("unable to overwrite keypair: %v", err)
	}

	return nil
}
