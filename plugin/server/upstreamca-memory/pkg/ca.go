package pkg

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/hcl"

	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/common/plugin"
	common "github.com/spiffe/spire/pkg/common/plugin"
	iface "github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/server/upstreamca"
	"log"
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
	TTL          string `hcl:"ttl" json:"ttl"` // time to live for generated certs
	TrustDomain  string `hcl:"trust_domain" json:"trust_domain"`
	CertFilePath string `hcl:"cert_file_path" json:"cert_file_path"`
	KeyFilePath  string `hcl:"key_file_path" json:"key_file_path"`
}

type memoryPlugin struct {
	config *configuration

	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	serial int64

	mtx *sync.RWMutex
}

func (m *memoryPlugin) Configure(req *common.ConfigureRequest) (*common.ConfigureResponse, error) {
	log.Print("Starting Configure")

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

	keyPEM, err := ioutil.ReadFile(config.KeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("Could not read %s: %s", config.KeyFilePath, err)
	}

	block, rest := pem.Decode(keyPEM)

	if block == nil {
		return nil, errors.New("Invalid cert format")
	}

	if len(rest) > 0 {
		return nil, errors.New("Invalid cert format: too many certs")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	certPEM, err := ioutil.ReadFile(config.CertFilePath)
	if err != nil {
		return nil, fmt.Errorf("Could not read %s: %s", config.CertFilePath, err)
	}

	block, rest = pem.Decode(certPEM)

	if block == nil {
		return nil, errors.New("Invalid cert format")
	}

	if len(rest) > 0 {
		return nil, errors.New("Invalid cert format: too many certs")
	}

	cert, err := x509.ParseCertificate(block.Bytes)

	// Set local vars from config struct
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.config = &configuration{}
	m.config.TrustDomain = config.TrustDomain
	m.config.TTL = config.TTL
	m.config.KeyFilePath = config.KeyFilePath
	m.config.CertFilePath = config.CertFilePath
	m.cert = cert
	m.key = key

	log.Print("Plugin successfully configured")
	return &common.ConfigureResponse{}, nil
}

func (*memoryPlugin) GetPluginInfo(req *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error) {
	log.Print("Getting plugin information")

	return &sriplugin.GetPluginInfoResponse{}, nil
}

func (m *memoryPlugin) SubmitCSR(request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	log.Print("Starting SubmitCSR")

	if m.cert == nil {
		return nil, errors.New("Invalid state: no cert")
	}

	if m.key == nil {
		return nil, errors.New("Invalid state: no key")
	}

	csr, err := ParseSpiffeCsr(request.Csr, m.config.TrustDomain)

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
		Issuer:          m.cert.Subject,
		SerialNumber:    big.NewInt(serial),
		NotBefore:       now,
		NotAfter:        now.Add(expiry),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader,
		&template, m.cert, csr.PublicKey, m.key)

	if err != nil {
		return nil, err
	}

	log.Print("Successfully created certificate")

	return &upstreamca.SubmitCSRResponse{
		Cert:                cert,
		UpstreamTrustBundle: m.cert.Raw,
	}, nil
}

func ParseSpiffeCsr(csrDER []byte, trustDomain string) (csr *x509.CertificateRequest, err error) {
	csr, err = x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}

	err = csr.CheckSignature()
	if err != nil {
		return nil, errors.New("Failed to check certificate request signature: " + err.Error())
	}

	urinames, err := uri.GetURINamesFromExtensions(&csr.Extensions)
	if err != nil {
		return nil, err
	}

	if len(urinames) != 1 {
		return nil, errors.New("The CSR must have exactly one URI SAN")
	}

	csrSpiffeID, err := url.Parse(urinames[0])
	if err != nil {
		return nil, err
	}

	log.Printf("Parsing CSR with SPIFFE ID: '%v'", csrSpiffeID.String())

	if csrSpiffeID.Scheme != "spiffe" {
		return nil, fmt.Errorf("SPIFFE ID '%v' is not prefixed with the spiffe:// scheme.", csrSpiffeID)
	}

	if csrSpiffeID.Host != trustDomain {
		return nil, fmt.Errorf("The SPIFFE ID '%v' does not reside in the trust domain '%v'.", urinames[0], trustDomain)
	}

	return csr, nil
}

func NewWithDefault(keyFilePath string, certFilePath string) (m upstreamca.UpstreamCa, err error) {
	config := configuration{
		TrustDomain:  "localhost",
		KeyFilePath:  keyFilePath,
		CertFilePath: certFilePath,
		TTL:          "1h",
	}

	jsonConfig, err := json.Marshal(config)
	pluginConfig := &iface.ConfigureRequest{
		Configuration: string(jsonConfig),
	}

	m = &memoryPlugin{
		mtx: &sync.RWMutex{},
	}

	_, err = m.Configure(pluginConfig)

	return m, err
}
