package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sync"
	"testing"

  "github.com/spiffe/go-spiffe"
	"github.com/spiffe/sri/helpers/testutil"
	"github.com/spiffe/sri/pkg/server/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	upca "github.com/spiffe/sri/plugin/server/upstreamca-memory/pkg"
)

func TestMemory_Configure(t *testing.T) {
	config := `{"trust_domain":"example.com", "ttl":3600000, "key_size":2048}`
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
	res, err := m.GetPluginInfo()
	require.NoError(t, err)
	assert.NotNil(t, res)
}

func TestMemory_GenerateCsr(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	csr, err := m.GenerateCsr()
	require.NoError(t, err)
	assert.NotEmpty(t, csr)
}

func TestMemory_LoadValidValidCertificate(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	const testDataDir = "_test_data/cert_valid"
	validCertFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	for _, validCertFile := range validCertFiles {
		certPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCertFile.Name()))
		require.NoError(t, err)
		err = m.LoadCertificate(certPEM)
		require.NoError(t, err)
	}
}

func TestMemory_LoadValidInvalidCertificate(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	const testDataDir = "_test_data/cert_invalid"
	validCertFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	for _, validCertFile := range validCertFiles {
		certPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, validCertFile.Name()))
		require.NoError(t, err)
		err = m.LoadCertificate(certPEM)
		require.Error(t, err)
	}
}

func TestMemory_FetchCertificate(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)
	cert, err := m.FetchCertificate()
	require.NoError(t, err)
	assert.Empty(t, cert)
}

func TestMemory_bootstrap(t *testing.T) {
	m, err := NewWithDefault()
	require.NoError(t, err)

	ca, err := upca.NewWithDefault()
	require.NoError(t, err)

	csr, err := m.GenerateCsr()
	require.NoError(t, err)

	cresp, err := ca.SubmitCSR(csr)
	require.NoError(t, err)

	err = m.LoadCertificate(cresp.Cert)
	require.NoError(t, err)

	lcert, err := m.FetchCertificate()
	require.NoError(t, err)

	assert.Equal(t, cresp.Cert, lcert)

	wcsr := createWorkloadCSR(t)

	wcert, err := m.SignCsr(wcsr)
	require.NoError(t, err)

	assert.NotEmpty(t, wcert)
}

func TestMemory_race(t *testing.T) {
	m := createDefault(t)

	ca, err := upca.NewWithDefault()
	require.NoError(t, err)

	csr, err := m.GenerateCsr()
	require.NoError(t, err)

	cresp, err := ca.SubmitCSR(csr)
	require.NoError(t, err)

	wcsr := createWorkloadCSR(t)

	testutil.RaceTest(t, func(t *testing.T) {
		m.GenerateCsr()
		m.LoadCertificate(cresp.Cert)
		m.FetchCertificate()
		m.SignCsr(wcsr)
	})
}

func createWorkloadCSR(t *testing.T) []byte {
	keysz := 1024
	key, err := rsa.GenerateKey(rand.Reader, keysz)
	require.NoError(t, err)

	uriSans, err := spiffe.MarshalUriSANs([]string{fmt.Sprintf("spiffe://localhost")})
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
				Critical: true,
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
