package pkg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"github.com/vrischmann/jsonutil"

	"github.com/spiffe/go-spiffe/uri"
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
	TTL          jsonutil.Duration `json:"ttl"` // time to live for generated certs
	TrustDomain  string            `json:"trust_domain"`
	KeySize      int               `json:"key_size"`
	CertSubject  pkix.Name         `json:"cert_subject"`
	CertFilePath string            `json:"cert_file_path"`
	KeyFilePath  string            `json:"key_file_path"`
}

type memoryPlugin struct {
	config *configuration

	key    *rsa.PrivateKey
	cert   *x509.Certificate
	serial int64

	mtx *sync.RWMutex
}

func (m *memoryPlugin) Configure(req *common.ConfigureRequest) (*common.ConfigureResponse, error) {
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
		return nil, err
	}

	block, rest := pem.Decode(keyPEM)

	if block == nil {
		return nil, errors.New("Invalid cert format")
	}

	if len(rest) > 0 {
		return nil, errors.New("Invalid cert format: too many certs")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	certPEM, err := ioutil.ReadFile(config.CertFilePath)
	if err != nil {
		return nil, err
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
	m.config.KeySize = config.KeySize
	m.config.CertSubject = config.CertSubject
	m.config.KeyFilePath = config.KeyFilePath
	m.config.CertFilePath = config.CertFilePath
	m.cert = cert
	m.key = key

	return &common.ConfigureResponse{}, nil
}

func (memoryPlugin) GetPluginInfo() (*sriplugin.GetPluginInfoResponse, error) {
	return &pluginInfo, nil
}

func (m *memoryPlugin) SubmitCSR(request *upstreamca.SubmitCSRRequest) (*upstreamca.SubmitCSRResponse, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

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

	template := x509.Certificate{
		ExtraExtensions: csr.Extensions,
		Subject:         csr.Subject,
		Issuer:          m.cert.Subject,
		SerialNumber:    big.NewInt(serial),
		NotBefore:       now,
		NotAfter:        now.Add(m.config.TTL.Duration),
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

	urinames, err := uri.GetURINamesFromExtensions(&csr.Extensions)
	if err != nil {
		return nil, err
	}

	if len(urinames) != 1 {
		return nil, errors.New("The CSR must have exactly one URI SAN")
	}

	csrSpiffeID, err := url.Parse(urinames[0])

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
		KeySize:      2048,
		TTL:          jsonutil.FromDuration(time.Hour),
		CertSubject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "",
		}}

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
