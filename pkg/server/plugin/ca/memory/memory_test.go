package memory

import (
	"context"
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
	"time"

	"github.com/spiffe/go-spiffe/uri"
	upca "github.com/spiffe/spire/pkg/server/plugin/upstreamca/disk"
	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/ca"
	"github.com/spiffe/spire/proto/server/upstreamca"
	testutil "github.com/spiffe/spire/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	ctx = context.Background()
)

func TestMemory_Configure(t *testing.T) {
	config := `{"trust_domain":"example.com", "key_size":2048}`
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
	}

	m := &MemoryPlugin{
		mtx: &sync.RWMutex{},
	}
	resp, err := m.Configure(ctx, pluginConfig)
	assert.Nil(t, err)
	assert.Equal(t, &spi.ConfigureResponse{}, resp)
}

func TestMemory_ConfigureParseHclError(t *testing.T) {
	config := "'" ///This should throw and error on parsing.
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
	}

	m := &MemoryPlugin{
		mtx: &sync.RWMutex{},
	}

	resp, err := m.Configure(ctx, pluginConfig)
	expectedError := "At 1:1: illegal char"
	expectedErrorList := []string{expectedError}

	assert.Equal(t, err.Error(), expectedError)
	assert.Equal(t, resp.GetErrorList(), expectedErrorList)
}

func TestMemory_ConfigureDecodeObjectError(t *testing.T) {
	config := `{"key_size": "foo"}` /// This should fail on decodeing object
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
	}

	m := &MemoryPlugin{
		mtx: &sync.RWMutex{},
	}

	resp, err := m.Configure(ctx, pluginConfig)
	expectedError := "strconv.ParseInt: parsing \"foo\": invalid syntax"
	expectedErrorList := []string{expectedError}

	assert.Equal(t, err.Error(), expectedError)
	assert.Equal(t, resp.GetErrorList(), expectedErrorList)
}

func TestMemory_GetPluginInfo(t *testing.T) {
	m := NewWithDefault()
	res, err := m.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	require.NoError(t, err)
	assert.NotNil(t, res)
}

func TestMemory_GenerateCsr(t *testing.T) {
	m := NewWithDefault()

	generateCsrResp, err := m.GenerateCsr(ctx, &ca.GenerateCsrRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, generateCsrResp.Csr)
}

func TestMemory_LoadValidCertificate(t *testing.T) {
	m := NewWithDefault()

	const testDataDir = "_test_data/cert_valid"
	validCertFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	m.GenerateCsr(ctx, &ca.GenerateCsrRequest{})

	for _, file := range validCertFiles {
		certPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, file.Name()))
		if assert.NoError(t, err, file.Name()) {
			block, rest := pem.Decode(certPEM)
			assert.Len(t, rest, 0, file.Name())
			_, err := m.LoadCertificate(ctx, &ca.LoadCertificateRequest{SignedIntermediateCert: block.Bytes})
			assert.NoError(t, err, file.Name())

			resp, err := m.FetchCertificate(ctx, &ca.FetchCertificateRequest{})
			require.NoError(t, err, file.Name())
			require.Equal(t, resp.StoredIntermediateCert, block.Bytes, file.Name())
		}
	}
}

func TestMemory_LoadInvalidCertificate(t *testing.T) {
	m := NewWithDefault()

	const testDataDir = "_test_data/cert_invalid"
	invalidCertFiles, err := ioutil.ReadDir(testDataDir)
	assert.NoError(t, err)

	for _, file := range invalidCertFiles {
		certPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, file.Name()))
		if assert.NoError(t, err, file.Name()) {
			block, rest := pem.Decode(certPEM)
			assert.Len(t, rest, 0, file.Name())
			_, err := m.LoadCertificate(ctx, &ca.LoadCertificateRequest{SignedIntermediateCert: block.Bytes})
			assert.Error(t, err, file.Name())
		}
	}
}

func TestMemory_FetchCertificate(t *testing.T) {
	m := NewWithDefault()
	cert, err := m.FetchCertificate(ctx, &ca.FetchCertificateRequest{})
	require.NoError(t, err)
	assert.Empty(t, cert.StoredIntermediateCert)
}

func TestMemory_bootstrap(t *testing.T) {
	m := NewWithDefault()

	upca, err := newUpCA("../../upstreamca/disk/_test_data/keys/private_key.pem", "../../upstreamca/disk/_test_data/keys/cert.pem")
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(ctx, &ca.GenerateCsrRequest{})
	require.NoError(t, err)

	submitCSRResp, err := upca.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: generateCsrResp.Csr})
	require.NoError(t, err)

	_, err = m.LoadCertificate(ctx, &ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})
	require.NoError(t, err)

	fetchCertificateResp, err := m.FetchCertificate(ctx, &ca.FetchCertificateRequest{})
	require.NoError(t, err)

	assert.Equal(t, submitCSRResp.Cert, fetchCertificateResp.StoredIntermediateCert)

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	wcert, err := m.SignCsr(ctx, &ca.SignCsrRequest{Csr: wcsr})
	require.NoError(t, err)

	assert.NotEmpty(t, wcert)
}

func TestMemory_race(t *testing.T) {
	m := NewWithDefault()

	upca, err := newUpCA("../../upstreamca/disk/_test_data/keys/private_key.pem", "../../upstreamca/disk/_test_data/keys/cert.pem")
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(ctx, &ca.GenerateCsrRequest{})
	require.NoError(t, err)

	submitCSRResp, err := upca.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: generateCsrResp.Csr})
	require.NoError(t, err)

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	testutil.RaceTest(t, func(t *testing.T) {
		m.GenerateCsr(ctx, &ca.GenerateCsrRequest{})
		m.LoadCertificate(ctx, &ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})
		m.FetchCertificate(ctx, &ca.FetchCertificateRequest{})
		m.SignCsr(ctx, &ca.SignCsrRequest{Csr: wcsr})
	})
}

func TestMemory_SignCsr(t *testing.T) {
	m := populateCert(t)

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	wcert, err := m.SignCsr(ctx, &ca.SignCsrRequest{Csr: wcsr})
	require.NoError(t, err)
	assert.NotEmpty(t, wcert)

	cert, err := x509.ParseCertificate(wcert.SignedCertificate)
	roots := getRoots(t, m)
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots})
	require.NoError(t, err)
}

func TestMemory_SignCsrWithProblematicTTL(t *testing.T) {
	m := populateCert(t)
	caResp, err := m.FetchCertificate(ctx, &ca.FetchCertificateRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, caResp.StoredIntermediateCert)
	caCert, err := x509.ParseCertificate(caResp.StoredIntermediateCert)
	require.NoError(t, err)

	ttl := time.Until(caCert.NotAfter.Add(1 * time.Hour))
	csr := createWorkloadCSR(t, "spiffe://localhost")
	sResp, err := m.SignCsr(ctx, &ca.SignCsrRequest{Csr: csr, Ttl: int32(ttl.Seconds())})
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(sResp.SignedCertificate)
	require.NoError(t, err)
	assert.Equal(t, caCert.NotAfter, cert.NotAfter)
}

func TestMemory_SignCsrExpire(t *testing.T) {
	m := populateCert(t)
	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	// Set a TTL of one second
	wcert, err := m.SignCsr(ctx, &ca.SignCsrRequest{Csr: wcsr, Ttl: 1})
	require.NoError(t, err)
	assert.NotEmpty(t, wcert)

	// Wait for two seconds. The certificate expires.
	time.Sleep(2 * time.Second)
	cert, err := x509.ParseCertificate(wcert.SignedCertificate)
	roots := getRoots(t, m)
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots})
	assert.Error(t, err)
}

func TestMemory_SignCsrNoCert(t *testing.T) {
	m := NewWithDefault()

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	wcert, err := m.SignCsr(ctx, &ca.SignCsrRequest{Csr: wcsr})

	assert.Error(t, err)
	assert.Empty(t, wcert)
}

func TestMemory_SignCsrErrorParsingSpiffeId(t *testing.T) {
	m := populateCert(t)

	wcsr := createWorkloadCSR(t, "spif://localhost")

	wcert, err := m.SignCsr(ctx, &ca.SignCsrRequest{Csr: wcsr})

	assert.Error(t, err)
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
	m := NewWithDefault()

	upca, err := newUpCA("../../upstreamca/disk/_test_data/keys/private_key.pem", "../../upstreamca/disk/_test_data/keys/cert.pem")
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(ctx, &ca.GenerateCsrRequest{})
	require.NoError(t, err)

	submitCSRResp, err := upca.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: generateCsrResp.Csr})
	require.NoError(t, err)

	submitCSRResp.Cert = []byte{}
	cert, err := m.LoadCertificate(ctx, &ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})

	assert.Equal(t, "asn1: syntax error: sequence truncated", err.Error())
	assert.Equal(t, &ca.LoadCertificateResponse{}, cert)
}

func TestMemory_LoadCertificateTooManyCerts(t *testing.T) {
	m := NewWithDefault()

	upca, err := newUpCA("../../upstreamca/disk/_test_data/keys/private_key.pem", "../../upstreamca/disk/_test_data/keys/cert.pem")
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(ctx, &ca.GenerateCsrRequest{})
	require.NoError(t, err)

	submitCSRResp, err := upca.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: generateCsrResp.Csr})
	require.NoError(t, err)

	oldCert := submitCSRResp.Cert
	submitCSRResp.Cert = append(oldCert, oldCert...)
	cert, err := m.LoadCertificate(ctx, &ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})

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

func populateCert(t *testing.T) (m ca.ServerCA) {
	m = NewWithDefault()

	upca, err := newUpCA("../../upstreamca/disk/_test_data/keys/private_key.pem", "../../upstreamca/disk/_test_data/keys/cert.pem")
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(ctx, &ca.GenerateCsrRequest{})
	require.NoError(t, err)

	submitCSRResp, err := upca.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: generateCsrResp.Csr})
	require.NoError(t, err)

	_, err = m.LoadCertificate(ctx, &ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})
	require.NoError(t, err)

	return m
}

func getRoots(t *testing.T, m ca.ServerCA) (roots *x509.CertPool) {
	fetchResp, err := m.FetchCertificate(ctx, &ca.FetchCertificateRequest{})
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(fetchResp.StoredIntermediateCert)
	require.NoError(t, err)
	roots = x509.NewCertPool()
	roots.AddCert(rootCert)

	return roots
}

func newUpCA(keyFilePath string, certFilePath string) (upstreamca.UpstreamCA, error) {
	config := upca.Configuration{
		TrustDomain:  "localhost",
		KeyFilePath:  keyFilePath,
		CertFilePath: certFilePath,
		TTL:          "1h",
	}

	jsonConfig, err := json.Marshal(config)
	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
	}

	m := upca.New()
	_, err = m.Configure(ctx, pluginConfig)
	return m, err
}
