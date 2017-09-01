package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spiffe/go-spiffe/spiffe"
	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/sri/helpers/testutil"
	iface "github.com/spiffe/sri/pkg/common/plugin"
	"github.com/spiffe/sri/pkg/server/ca"
	"github.com/spiffe/sri/pkg/server/upstreamca"
	upca "github.com/spiffe/sri/plugin/server/upstreamca-memory/pkg"
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
		cert, err := ioutil.ReadFile(filepath.Join(testDataDir, file.Name()))
		if assert.NoError(t, err, file.Name()) {
			_, err := m.LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: cert})
			assert.NoError(t, err, file.Name())
		}

		resp, err := m.FetchCertificate(&ca.FetchCertificateRequest{})
		require.NoError(t, err)
		require.Equal(t, resp.StoredIntermediateCert, cert)
	}
}

func TestMemory_LoadInvalidCertificate(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	const testDataDir = "_test_data/cert_invalid"
	invalidCertFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	for _, file := range invalidCertFiles {
		cert, err := ioutil.ReadFile(filepath.Join(testDataDir, file.Name()))
		if assert.NoError(t, err, file.Name()) {
			_, err := m.LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: cert})
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

	wcsr := createWorkloadCSR(t)

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

	wcsr := createWorkloadCSR(t)

	testutil.RaceTest(t, func(t *testing.T) {
		m.GenerateCsr(&ca.GenerateCsrRequest{})
		m.LoadCertificate(&ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})
		m.FetchCertificate(&ca.FetchCertificateRequest{})
		m.SignCsr(&ca.SignCsrRequest{Csr: wcsr})
	})
}

func createWorkloadCSR(t *testing.T) []byte {
	keysz := 1024
	key, err := rsa.GenerateKey(rand.Reader, keysz)
	require.NoError(t, err)

	uriSans, err := uri.MarshalUriSANs([]string{"spiffe://localhost"})
	require.NoError(t, err)

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "workload",
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       spiffe.OidExtensionSubjectAltName,
				Value:    uriSans,
				Critical: false,
			}},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
}
