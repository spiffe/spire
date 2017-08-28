package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/spiffe/sri/helpers/testutil"
	"github.com/spiffe/sri/pkg/server/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	upca "github.com/spiffe/sri/plugin/server/upstreamca-memory/pkg"
)

func TestMemory_Configure(t *testing.T) {
	t.SkipNow()
}

func TestMemory_GetPluginInfo(t *testing.T) {
	m := createDefault(t)
	res, err := m.GetPluginInfo()
	require.NoError(t, err)
	assert.NotNil(t, res)
}

func TestMemory_GenerateCsr(t *testing.T) {
	m := createDefault(t)
	csr, err := m.GenerateCsr()
	require.NoError(t, err)
	assert.NotEmpty(t, csr)
}

func TestMemory_FetchCertificate(t *testing.T) {
	m := createDefault(t)
	cert, err := m.FetchCertificate()
	require.NoError(t, err)
	assert.Empty(t, cert)
}

func TestMemory_bootstrap(t *testing.T) {
	m := createDefault(t)

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

func createDefault(t *testing.T) ca.ControlPlaneCa {
	m, err := NewWithDefault()
	require.NoError(t, err)
	return m
}

func createWorkloadCSR(t *testing.T) []byte {
	keysz := 1024
	key, err := rsa.GenerateKey(rand.Reader, keysz)
	require.NoError(t, err)

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIFFE"},
			CommonName:   "workload",
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})
}
