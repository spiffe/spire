package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spiffe/go-spiffe/uri"
	iface "github.com/spiffe/spire/pkg/common/plugin"
	"github.com/spiffe/spire/pkg/common/testutil"
	upca "github.com/spiffe/spire/plugin/server/upstreamca-memory/pkg"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/upstreamca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemory_Configure(t *testing.T) {
	config := `{"trust_domain":"example.com", "ttl":"1h", "key_size":2048}`
	pluginConfig := &iface.ConfigureRequest{
		Configuration: config,
	}

	m := &memoryPlugin{
		mtx: &sync.RWMutex{},
	}
	resp, err := m.Configure(pluginConfig)
	assert.Nil(t, err)
	assert.Equal(t, &iface.ConfigureResponse{}, resp)
}

func TestMemory_ConfigureParseHclError(t *testing.T) {
	config := "'" ///This should throw and error on parsing.
	pluginConfig := &iface.ConfigureRequest{
		Configuration: config,
	}

	m := &memoryPlugin{
		mtx: &sync.RWMutex{},
	}

	resp, err := m.Configure(pluginConfig)
	expectedError := "At 1:1: illegal char"
	expectedErrorList := []string{expectedError}

	assert.Equal(t, err.Error(), expectedError)
	assert.Equal(t, resp.GetErrorList(), expectedErrorList)
}

func TestMemory_ConfigureDecodeObjectError(t *testing.T) {
	config := `{"key_size": "foo"}` /// This should fail on decodeing object
	pluginConfig := &iface.ConfigureRequest{
		Configuration: config,
	}

	m := &memoryPlugin{
		mtx: &sync.RWMutex{},
	}

	resp, err := m.Configure(pluginConfig)
	expectedError := "strconv.ParseInt: parsing \"foo\": invalid syntax"
	expectedErrorList := []string{expectedError}

	assert.Equal(t, err.Error(), expectedError)
	assert.Equal(t, resp.GetErrorList(), expectedErrorList)
}

func TestMemory_GetPluginInfo(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)
	res, err := m.GetPluginInfo(&iface.GetPluginInfoRequest{})
	require.NoError(t, err)
	assert.NotNil(t, res)
}

func TestMemory_GenerateCsr(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(&ca.GenerateCsrRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, generateCsrResp.Csr)
}

func TestMemory_LoadValidCertificate(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	const testDataDir = "_test_data/cert_valid"
	validCertFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	m.GenerateCsr(&ca.GenerateCsrRequest{})

	for _, file := range validCertFiles {
		certPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, file.Name()))
		if assert.NoError(t, err, file.Name()) {
			block, rest := pem.Decode(certPEM)
			assert.Len(t, rest, 0, file.Name())
			_, err := m.LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: block.Bytes})
			assert.NoError(t, err, file.Name())

			resp, err := m.FetchCertificate(&ca.FetchCertificateRequest{})
			require.NoError(t, err, file.Name())
			require.Equal(t, resp.StoredIntermediateCert, block.Bytes, file.Name())
		}
	}
}

func TestMemory_LoadInvalidCertificate(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	const testDataDir = "_test_data/cert_invalid"
	invalidCertFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	for _, file := range invalidCertFiles {
		certPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, file.Name()))
		if assert.NoError(t, err, file.Name()) {
			block, rest := pem.Decode(certPEM)
			assert.Len(t, rest, 0, file.Name())
			_, err := m.LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: block.Bytes})
			assert.Error(t, err, file.Name())
		}
	}
}

func TestMemory_FetchCertificate(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)
	cert, err := m.FetchCertificate(&ca.FetchCertificateRequest{})
	require.NoError(t, err)
	assert.Empty(t, cert.StoredIntermediateCert)
}

func TestMemory_bootstrap(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	upca, err := upca.NewWithDefault("../upstreamca-memory/pkg/_test_data/keys/private_key.pem", "../upstreamca-memory/pkg/_test_data/keys/cert.pem")
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(&ca.GenerateCsrRequest{})
	require.NoError(t, err)

	submitCSRResp, err := upca.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: generateCsrResp.Csr})
	require.NoError(t, err)

	_, err = m.LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})
	require.NoError(t, err)

	fetchCertificateResp, err := m.FetchCertificate(&ca.FetchCertificateRequest{})
	require.NoError(t, err)

	assert.Equal(t, submitCSRResp.Cert, fetchCertificateResp.StoredIntermediateCert)

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	wcert, err := m.SignCsr(&ca.SignCsrRequest{Csr: wcsr})
	require.NoError(t, err)

	assert.NotEmpty(t, wcert)
}

func TestMemory_race(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	upca, err := upca.NewWithDefault("../upstreamca-memory/pkg/_test_data/keys/private_key.pem", "../upstreamca-memory/pkg/_test_data/keys/cert.pem")
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(&ca.GenerateCsrRequest{})
	require.NoError(t, err)

	submitCSRResp, err := upca.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: generateCsrResp.Csr})
	require.NoError(t, err)

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	testutil.RaceTest(t, func(t *testing.T) {
		m.GenerateCsr(&ca.GenerateCsrRequest{})
		m.LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})
		m.FetchCertificate(&ca.FetchCertificateRequest{})
		m.SignCsr(&ca.SignCsrRequest{Csr: wcsr})
	})
}

func TestMemory_SignCsr(t *testing.T) {
	m := populateCert(t)

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	wcert, err := m.SignCsr(&ca.SignCsrRequest{Csr: wcsr})
	require.NoError(t, err)

	assert.NotEmpty(t, wcert)
}

func TestMemory_SignCsrNoCert(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	wcert, err := m.SignCsr(&ca.SignCsrRequest{Csr: wcsr})

	assert.Equal(t, "Invalid state: no certificate", err.Error())
	assert.Empty(t, wcert)
}

func TestMemory_SignCsrErrorParsingSpiffeId(t *testing.T) {
	m := populateCert(t)

	wcsr := createWorkloadCSR(t, "spif://localhost")

	wcert, err := m.SignCsr(&ca.SignCsrRequest{Csr: wcsr})

	assert.Equal(t, "SPIFFE ID 'spif://localhost' is not prefixed with the spiffe:// scheme.", err.Error())
	assert.Empty(t, wcert)
}

func TestMemory_SignCsrErrorParsingTTL(t *testing.T) {
	m := populateCert(t)

	config := configuration{
		TrustDomain: "localhost",
		KeySize:     2048,
		TTL:         "abc",
		CertSubject: certSubjectConfig{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "",
		}}

	pluginConfig, err := populateConfigPlugin(config)
	_, err = m.Configure(pluginConfig)
	require.NoError(t, err)

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	wcert, err := m.SignCsr(&ca.SignCsrRequest{Csr: wcsr})

	assert.Equal(t, "Unable to parse TTL: time: invalid duration abc", err.Error())
	assert.Empty(t, wcert)
}

/// This is supposed to test a failure on line 136, but its quite hard to inject a
/// failure without changing the function considerably.
/// Test left as documentation.
///
// func TestMemory_SignCsrErrorCreatingCertificate(t *testing.T) {}

/// This would test the error case where we are unable to Marshal
/// the uriSANS on line 169. However we are unable to inject a failure
/// here to test.
/// Test left as documentation.
///
// func TestMemory_GenerateCsrBadSpiffeURI(t *testing.T) {}

/// This would test line 191 however we are unable to inject failures without
/// changing the function considerably.
///Test left as documentation.
///
//func TestMemory_GenerateCsrCreateCertificateRequestError(t *testing.T) {}

func TestMemory_LoadCertificateInvalidCertFormat(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	upca, err := upca.NewWithDefault("../upstreamca-memory/pkg/_test_data/keys/private_key.pem", "../upstreamca-memory/pkg/_test_data/keys/cert.pem")
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(&ca.GenerateCsrRequest{})
	require.NoError(t, err)

	submitCSRResp, err := upca.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: generateCsrResp.Csr})
	require.NoError(t, err)

	submitCSRResp.Cert = []byte{}
	cert, err := m.LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})

	assert.Equal(t, "asn1: syntax error: sequence truncated", err.Error())
	assert.Equal(t, &ca.LoadCertificateResponse{}, cert)
}

func TestMemory_LoadCertificateTooManyCerts(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	upca, err := upca.NewWithDefault("../upstreamca-memory/pkg/_test_data/keys/private_key.pem", "../upstreamca-memory/pkg/_test_data/keys/cert.pem")
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(&ca.GenerateCsrRequest{})
	require.NoError(t, err)

	submitCSRResp, err := upca.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: generateCsrResp.Csr})
	require.NoError(t, err)

	oldCert := submitCSRResp.Cert
	submitCSRResp.Cert = append(oldCert, oldCert...)
	cert, err := m.LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})

	assert.Equal(t, "asn1: syntax error: trailing data", err.Error())
	assert.Equal(t, &ca.LoadCertificateResponse{}, cert)
}

///
// Test helper functions
///

func createWorkloadCSR(t *testing.T, spiffeID string) []byte {
	keysz := 1024
	key, err := rsa.GenerateKey(rand.Reader, keysz)
	require.NoError(t, err)

	uriSans, err := uri.MarshalUriSANs([]string{spiffeID})
	require.NoError(t, err)

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "workload",
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       uri.OidExtensionSubjectAltName,
				Value:    uriSans,
				Critical: false,
			}},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	require.NoError(t, err)

	return csr
}

func populateCert(t *testing.T) (m ca.ControlPlaneCa) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	upca, err := upca.NewWithDefault("../upstreamca-memory/pkg/_test_data/keys/private_key.pem", "../upstreamca-memory/pkg/_test_data/keys/cert.pem")
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(&ca.GenerateCsrRequest{})
	require.NoError(t, err)

	submitCSRResp, err := upca.SubmitCSR(&upstreamca.SubmitCSRRequest{Csr: generateCsrResp.Csr})
	require.NoError(t, err)

	_, err = m.LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})
	require.NoError(t, err)

	return m
}

func populateConfigPlugin(config configuration) (p *iface.ConfigureRequest, err error) {
	jsonConfig, err := json.Marshal(config)

	pluginConfig := &iface.ConfigureRequest{
		Configuration: string(jsonConfig),
	}

	return pluginConfig, err
}
