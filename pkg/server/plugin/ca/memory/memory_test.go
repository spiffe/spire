package memory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/uri"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
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

	m := New()
	resp, err := m.Configure(ctx, pluginConfig)
	assert.Nil(t, err)
	assert.Equal(t, &spi.ConfigureResponse{}, resp)
}

func TestMemory_ConfigureDecodeError(t *testing.T) {
	config := `{"default_ttl": "foo"}` /// This should fail on decoding object
	pluginConfig := &spi.ConfigureRequest{
		Configuration: config,
	}

	m := New()

	resp, err := m.Configure(ctx, pluginConfig)
	require.EqualError(t, err, "unable to decode configuration: strconv.ParseInt: parsing \"foo\": invalid syntax")
	require.Nil(t, resp)
}

func TestMemory_GetPluginInfo(t *testing.T) {
	m := NewWithDefault()
	resp, err := m.GetPluginInfo(ctx, &spi.GetPluginInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
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

	for _, file := range validCertFiles {
		m.GenerateCsr(ctx, &ca.GenerateCsrRequest{})
		certPEM, err := ioutil.ReadFile(filepath.Join(testDataDir, file.Name()))
		if assert.NoError(t, err, file.Name()) {
			block, rest := pem.Decode(certPEM)
			assert.Len(t, rest, 0, file.Name())
			_, err := m.LoadCertificate(ctx, &ca.LoadCertificateRequest{SignedIntermediateCert: block.Bytes})
			assert.NoError(t, err, file.Name())

			cert, err := m.getX509SVIDCertificate()
			require.NoError(t, err)
			require.Equal(t, cert.Raw, block.Bytes, file.Name())
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

	cert, err := m.getX509SVIDCertificate()
	require.NoError(t, err)

	assert.Equal(t, submitCSRResp.Cert, cert.Raw)

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	wcert, err := m.SignX509SvidCsr(ctx, &ca.SignX509SvidCsrRequest{Csr: wcsr})
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
		m.SignX509SvidCsr(ctx, &ca.SignX509SvidCsrRequest{Csr: wcsr})
	})
}

func TestMemory_SignX509SvidCsr(t *testing.T) {
	m := populateCert(t)

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	wcert, err := m.SignX509SvidCsr(ctx, &ca.SignX509SvidCsrRequest{Csr: wcsr})
	require.NoError(t, err)
	assert.NotEmpty(t, wcert)

	cert, err := x509.ParseCertificate(wcert.SignedCertificate)
	require.NoError(t, err)
	roots := getRoots(t, m)
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots})
	require.NoError(t, err)
}

func TestMemory_SignX509SvidCsrWithProblematicTTL(t *testing.T) {
	m := populateCert(t)
	caCert, err := m.getX509SVIDCertificate()
	require.NoError(t, err)

	ttl := time.Until(caCert.NotAfter.Add(1 * time.Hour))
	csr := createWorkloadCSR(t, "spiffe://localhost")
	sResp, err := m.SignX509SvidCsr(ctx, &ca.SignX509SvidCsrRequest{Csr: csr, Ttl: int32(ttl.Seconds())})
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(sResp.SignedCertificate)
	require.NoError(t, err)
	assert.Equal(t, caCert.NotAfter, cert.NotAfter)
}

func TestMemory_SignX509SvidCsrExpire(t *testing.T) {
	m := populateCert(t)
	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	// Set a TTL of one second
	wcert, err := m.SignX509SvidCsr(ctx, &ca.SignX509SvidCsrRequest{Csr: wcsr, Ttl: 1})
	require.NoError(t, err)
	assert.NotEmpty(t, wcert)

	// Verify as if two seconds had elapsed and assert that the certificate
	// has expired.
	cert, err := x509.ParseCertificate(wcert.SignedCertificate)
	roots := getRoots(t, m)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now().Add(time.Second * 2),
	})
	assert.Error(t, err)
}

func TestMemory_SignX509SvidCsrNoCert(t *testing.T) {
	m := NewWithDefault()

	wcsr := createWorkloadCSR(t, "spiffe://localhost")

	wcert, err := m.SignX509SvidCsr(ctx, &ca.SignX509SvidCsrRequest{Csr: wcsr})
	assert.Error(t, err)
	assert.Nil(t, wcert)
}

func TestMemory_SignX509SvidCsrErrorParsingSpiffeId(t *testing.T) {
	m := populateCert(t)

	wcsr := createWorkloadCSR(t, "spif://localhost")

	wcert, err := m.SignX509SvidCsr(ctx, &ca.SignX509SvidCsrRequest{Csr: wcsr})
	assert.Error(t, err)
	assert.Nil(t, wcert)
}

/// This is supposed to test a failure on line 136, but its quite hard to inject a
/// failure without changing the function considerably.
/// Test left as documentation.
///
// func TestMemory_SignX509SvidCsrErrorCreatingCertificate(t *testing.T) {}

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
	resp, err := m.LoadCertificate(ctx, &ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})

	require.EqualError(t, err, "unable to parse server CA certificate: asn1: syntax error: sequence truncated")
	require.Nil(t, resp)
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
	resp, err := m.LoadCertificate(ctx, &ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})

	require.EqualError(t, err, "unable to parse server CA certificate: asn1: syntax error: trailing data")
	require.Nil(t, resp)
}

func TestMemory_SignJwtSvid(t *testing.T) {
	m := NewWithDefault()

	now := time.Now()
	m.hooks.now = func() time.Time {
		return now
	}

	goodRequest := &ca.SignJwtSvidRequest{
		SpiffeId: "spiffe://example.org/blog",
		Ttl:      1,
		Audience: []string{"spiffe://example.org/db"},
	}

	// no certificate loaded
	resp, err := m.SignJwtSvid(ctx, goodRequest)
	require.EqualError(t, err, "Invalid state: no certificate")
	require.Nil(t, resp)

	// load cert
	loadCert(t, m)

	// No SPIFFE ID
	resp, err = m.SignJwtSvid(ctx, &ca.SignJwtSvidRequest{
		Ttl:      1,
		Audience: []string{"spiffe://example.org/db"},
	})
	require.EqualError(t, err, "Invalid request: SPIFFE ID is required")
	require.Nil(t, resp)

	// Invalid expiration
	resp, err = m.SignJwtSvid(ctx, &ca.SignJwtSvidRequest{
		SpiffeId: "spiffe://example.org/blog",
		Ttl:      -1,
		Audience: []string{"spiffe://example.org/db"},
	})
	require.EqualError(t, err, "Invalid request: TTL is invalid")
	require.Nil(t, resp)

	// No audience
	resp, err = m.SignJwtSvid(ctx, &ca.SignJwtSvidRequest{
		SpiffeId: "spiffe://example.org/blog",
	})
	require.EqualError(t, err, "Invalid request: at least one audience is required")
	require.Nil(t, resp)

	// success
	resp, err = m.SignJwtSvid(ctx, goodRequest)
	require.NoError(t, err)
	require.NotEmpty(t, resp.SignedJwt)

	// validate returned token against trust bundle and assert that the proper
	// claims were added.
	cert, err := m.getJWTASVIDCertificate()
	require.NoError(t, err)
	trustBundle := jwtsvid.NewSimpleTrustBundle([]*x509.Certificate{
		cert,
	})
	claims, err := jwtsvid.ValidateSimpleToken(ctx, resp.SignedJwt, trustBundle, "spiffe://example.org/db")
	require.NoError(t, err)
	require.NotNil(t, claims)
	exp, err := json.Number(fmt.Sprint(now.Add(time.Second).Unix())).Float64()
	require.NoError(t, err)
	require.Len(t, claims, 3)
	require.Equal(t, "spiffe://example.org/blog", claims["sub"])
	require.Equal(t, "spiffe://example.org/db", claims["aud"])
	require.Equal(t, exp, claims["exp"])
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

func populateCert(t *testing.T) (m *MemoryPlugin) {
	m = NewWithDefault()
	loadCert(t, m)
	return m
}

func loadCert(t *testing.T, m *MemoryPlugin) {
	upca, err := newUpCA("../../upstreamca/disk/_test_data/keys/private_key.pem", "../../upstreamca/disk/_test_data/keys/cert.pem")
	require.NoError(t, err)

	generateCsrResp, err := m.GenerateCsr(ctx, &ca.GenerateCsrRequest{})
	require.NoError(t, err)

	submitCSRResp, err := upca.SubmitCSR(ctx, &upstreamca.SubmitCSRRequest{Csr: generateCsrResp.Csr})
	require.NoError(t, err)

	_, err = m.LoadCertificate(ctx, &ca.LoadCertificateRequest{SignedIntermediateCert: submitCSRResp.Cert})
	require.NoError(t, err)
}

func getRoots(t *testing.T, m *MemoryPlugin) (roots *x509.CertPool) {
	cert, err := m.getX509SVIDCertificate()
	require.NoError(t, err)
	roots = x509.NewCertPool()
	roots.AddCert(cert)

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
	if err != nil {
		return nil, err
	}
	pluginConfig := &spi.ConfigureRequest{
		Configuration: string(jsonConfig),
	}

	m := upca.New()
	_, err = m.Configure(ctx, pluginConfig)
	return m, err
}
