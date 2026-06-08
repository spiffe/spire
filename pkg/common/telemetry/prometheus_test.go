package telemetry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	prommetrics "github.com/hashicorp/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPrometheusRunner(t *testing.T) {
	config := testPrometheusConfig()
	pr, err := newTestPrometheusRunner(config)
	assert.Nil(t, err)
	assert.NotNil(t, pr)

	// It works when not configured
	config.FileConfig.Prometheus = nil
	pr, err = newTestPrometheusRunner(config)
	assert.Nil(t, err)
	assert.NotNil(t, pr)
}

func TestIsConfigured(t *testing.T) {
	config := testPrometheusConfig()

	pr, err := newTestPrometheusRunner(config)
	require.NoError(t, err)
	assert.True(t, pr.isConfigured())

	config.FileConfig.Prometheus = nil
	pr, err = newTestPrometheusRunner(config)
	require.NoError(t, err)
	assert.False(t, pr.isConfigured())
}

func TestRun(t *testing.T) {
	config := testPrometheusConfig()

	pr, err := newTestPrometheusRunner(config)
	require.NoError(t, err)

	errCh := make(chan error)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		errCh <- pr.run(ctx)
	}()

	// It stops when it's supposed to
	cancel()
	select {
	case err := <-errCh:
		assert.Equal(t, context.Canceled, err)
	case <-time.After(time.Minute):
		t.Fatal("timeout waiting for shutdown")
	}

	config.FileConfig.Prometheus = nil
	pr, err = newTestPrometheusRunner(config)
	require.NoError(t, err)

	go func() {
		errCh <- pr.run(context.Background())
	}()

	// It doesn't run if it's not configured
	select {
	case err := <-errCh:
		assert.Nil(t, err, "should be nil if not configured")
	case <-time.After(time.Minute):
		t.Fatal("prometheus running but not configured")
	}
}

func testPrometheusConfig() *MetricsConfig {
	l, _ := test.NewNullLogger()

	return &MetricsConfig{
		Logger:      l,
		ServiceName: "foo",
		TrustDomain: "test.org",
		FileConfig: FileConfig{
			// Let prometheus listen on a random port
			Prometheus: &PrometheusConfig{},
		},
	}
}

// newTestPrometheusRunner wraps newPrometheusRunner, unregistering the
// collector after creation in order to avoid duplicate registration errors
func newTestPrometheusRunner(c *MetricsConfig) (sinkRunner, error) {
	runner, err := newPrometheusRunner(c)

	if runner != nil && runner.isConfigured() {
		pr := runner.(*prometheusRunner)
		sink := pr.sink.(*prommetrics.PrometheusSink)
		prometheus.Unregister(sink)
	}

	return runner, err
}

func TestPrometheusTLSConfig(t *testing.T) {
	tests := []struct {
		name             string
		setupTLS         func(t *testing.T) *TLSConfig
		expectError      bool
		errorMsgContains string
		validateTLS      func(t *testing.T, runner *prometheusRunner)
	}{
		{
			name: "testing TLS without CA cert",
			setupTLS: func(t *testing.T) *TLSConfig {
				certFile, keyFile := createTestCertAndKey(t)
				return &TLSConfig{
					CertFile:     certFile,
					KeyFile:      keyFile,
					ClientCAFile: "", // No CA file
				}
			},
			expectError: false,
			validateTLS: func(t *testing.T, runner *prometheusRunner) {
				require.NotNil(t, runner.server.TLSConfig)
				assert.NotNil(t, runner.server.TLSConfig.Certificates)
				assert.Len(t, runner.server.TLSConfig.Certificates, 1)
				// ClientCAs should be nil when CAFile is not provided
				assert.Nil(t, runner.server.TLSConfig.ClientCAs)
				// ClientAuth should not be set when CAFile is not provided
				assert.Equal(t, tls.NoClientCert, runner.server.TLSConfig.ClientAuth)
			},
		},
		{
			name: "testing TLS with CA cert, mTLS",
			setupTLS: func(t *testing.T) *TLSConfig {
				certFile, keyFile := createTestCertAndKey(t)
				caFile := createTestCA(t)
				return &TLSConfig{
					CertFile:     certFile,
					KeyFile:      keyFile,
					ClientCAFile: caFile,
				}
			},
			expectError: false,
			validateTLS: func(t *testing.T, runner *prometheusRunner) {
				require.NotNil(t, runner.server.TLSConfig)
				assert.NotNil(t, runner.server.TLSConfig.Certificates)
				assert.Len(t, runner.server.TLSConfig.Certificates, 1)
				// ClientCAs should be set when CAFile is provided
				assert.NotNil(t, runner.server.TLSConfig.ClientCAs)
				// ClientAuth should require client cert when CAFile is provided
				assert.Equal(t, tls.RequireAndVerifyClientCert, runner.server.TLSConfig.ClientAuth)
			},
		},
		{
			name: "testing TLS with missing cert file",
			setupTLS: func(t *testing.T) *TLSConfig {
				return &TLSConfig{
					CertFile:     "/nonexistent/cert.pem",
					KeyFile:      "/nonexistent/key.pem",
					ClientCAFile: "",
				}
			},
			expectError: true,
			// error message in windows: The system cannot find the path specified.
			// error message in linux: no such file or directory
			errorMsgContains: "failed to create TLS config for Prometheus: open /nonexistent/cert.pem:",
		},
		{
			name: "testing TLS with invalid cert/key files",
			setupTLS: func(t *testing.T) *TLSConfig {
				// Create invalid cert/key files
				certFile := createTempFile(t, []byte("invalid cert data"))
				keyFile := createTempFile(t, []byte("invalid key data"))
				return &TLSConfig{
					CertFile:     certFile,
					KeyFile:      keyFile,
					ClientCAFile: "",
				}
			},
			expectError:      true,
			errorMsgContains: "failed to create TLS config for Prometheus: tls: failed to find any PEM data in certificate input",
		},
		{
			name: "testing TLS with missing key file",
			setupTLS: func(t *testing.T) *TLSConfig {
				certFile, _ := createTestCertAndKey(t)
				return &TLSConfig{
					CertFile:     certFile,
					KeyFile:      "/nonexistent/key.pem",
					ClientCAFile: "",
				}
			},
			expectError: true,
			// error message in windows: The system cannot find the path specified.
			// error message in linux: no such file or directory
			errorMsgContains: "failed to create TLS config for Prometheus: open /nonexistent/key.pem:",
		},
		{
			name: "testing TLS with invalid CA file",
			setupTLS: func(t *testing.T) *TLSConfig {
				certFile, keyFile := createTestCertAndKey(t)
				invalidCAFile := createTempFile(t, []byte("invalid CA data"))
				return &TLSConfig{
					CertFile:     certFile,
					KeyFile:      keyFile,
					ClientCAFile: invalidCAFile,
				}
			},
			expectError:      true,
			errorMsgContains: "failed to create TLS config for Prometheus: no certificates found in file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig := tt.setupTLS(t)
			config := testPrometheusConfig()
			config.FileConfig.Prometheus.TLS = tlsConfig

			runner, err := newTestPrometheusRunner(config)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsgContains != "" {
					assert.Contains(t, err.Error(), tt.errorMsgContains, "actual error msg: %q", err.Error())
				}
				// When there's an error, runner should still be returned but TLS should not be configured
				if runner != nil {
					pr := runner.(*prometheusRunner)
					assert.Nil(t, pr.server.TLSConfig, "actual TLS config: %v", pr.server.TLSConfig)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, runner)
				pr := runner.(*prometheusRunner)
				if tt.validateTLS != nil {
					tt.validateTLS(t, pr)
				}
			}
		})
	}
}

func TestPrometheusSPIFFETLSConfig(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	foreignTD := spiffeid.RequireTrustDomainFromString("foreign.example.org")

	serverCA := testca.New(t, td)
	foreignCA := testca.New(t, foreignTD)

	serverSVID := serverCA.CreateX509SVID(spiffeid.RequireFromPath(td, "/spire/server"))
	allowedClientSVID := foreignCA.CreateX509SVID(spiffeid.RequireFromPath(foreignTD, "/prometheus"))
	disallowedClientSVID := serverCA.CreateX509SVID(spiffeid.RequireFromPath(td, "/other-client"))

	tests := []struct {
		name        string
		setupConfig func(*MetricsConfig)
		validateTLS func(t *testing.T, runner *prometheusRunner)
	}{
		{
			name: "use SPIRE SVID without client allowlist",
			setupConfig: func(config *MetricsConfig) {
				config.FileConfig.Prometheus.TLS = &TLSConfig{
					UseSPIRESVID: true,
				}
				config.GetX509SVID = func() (*x509svid.SVID, error) {
					return serverSVID, nil
				}
			},
			validateTLS: func(t *testing.T, runner *prometheusRunner) {
				require.NotNil(t, runner.server.TLSConfig)
				certificate, err := runner.server.TLSConfig.GetCertificate(&tls.ClientHelloInfo{})
				require.NoError(t, err)
				require.NotNil(t, certificate)
				assert.Equal(t, serverSVID.Certificates[0].Raw, certificate.Certificate[0])
				assert.Equal(t, tls.NoClientCert, runner.server.TLSConfig.ClientAuth)
				assert.True(t, runner.server.TLSConfig.SessionTicketsDisabled)
			},
		},
		{
			name: "use SPIRE SVID with authorized SPIFFE IDs",
			setupConfig: func(config *MetricsConfig) {
				config.FileConfig.Prometheus.TLS = &TLSConfig{
					UseSPIRESVID:        true,
					AuthorizedSPIFFEIDs: []string{allowedClientSVID.ID.String()},
				}
				config.GetX509SVID = func() (*x509svid.SVID, error) {
					return serverSVID, nil
				}
				config.GetX509BundleAuthorities = func(td spiffeid.TrustDomain) ([]*x509.Certificate, error) {
					switch td {
					case serverCA.X509Bundle().TrustDomain():
						return serverCA.X509Authorities(), nil
					case foreignCA.X509Bundle().TrustDomain():
						return foreignCA.X509Authorities(), nil
					default:
						return nil, nil
					}
				}
			},
			validateTLS: func(t *testing.T, runner *prometheusRunner) {
				require.NotNil(t, runner.server.TLSConfig)
				assert.Equal(t, tls.RequireAnyClientCert, runner.server.TLSConfig.ClientAuth)
				assert.True(t, runner.server.TLSConfig.SessionTicketsDisabled)
				require.NoError(t, runner.server.TLSConfig.VerifyPeerCertificate(rawCerts(allowedClientSVID.Certificates), nil))
				require.Error(t, runner.server.TLSConfig.VerifyPeerCertificate(rawCerts(disallowedClientSVID.Certificates), nil))
			},
		},
		{
			name: "use web certificate with authorized SPIFFE IDs",
			setupConfig: func(config *MetricsConfig) {
				certFile, keyFile := createTestCertAndKey(t)
				config.FileConfig.Prometheus.TLS = &TLSConfig{
					CertFile:            certFile,
					KeyFile:             keyFile,
					AuthorizedSPIFFEIDs: []string{allowedClientSVID.ID.String()},
				}
				config.GetX509BundleAuthorities = func(td spiffeid.TrustDomain) ([]*x509.Certificate, error) {
					switch td {
					case foreignCA.X509Bundle().TrustDomain():
						return foreignCA.X509Authorities(), nil
					default:
						return nil, nil
					}
				}
			},
			validateTLS: func(t *testing.T, runner *prometheusRunner) {
				require.NotNil(t, runner.server.TLSConfig)
				assert.Len(t, runner.server.TLSConfig.Certificates, 1)
				assert.Equal(t, tls.RequireAnyClientCert, runner.server.TLSConfig.ClientAuth)
				assert.True(t, runner.server.TLSConfig.SessionTicketsDisabled)
				require.NoError(t, runner.server.TLSConfig.VerifyPeerCertificate(rawCerts(allowedClientSVID.Certificates), nil))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testPrometheusConfig()
			tt.setupConfig(config)

			runner, err := newTestPrometheusRunner(config)
			require.NoError(t, err)
			require.NotNil(t, runner)

			tt.validateTLS(t, runner.(*prometheusRunner))
		})
	}
}

func TestPrometheusTLSConfigValidation(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	serverCA := testca.New(t, td)
	serverSVID := serverCA.CreateX509SVID(spiffeid.RequireFromPath(td, "/spire/server"))

	tests := []struct {
		name             string
		setupConfig      func(*MetricsConfig)
		errorMsgContains string
	}{
		{
			name: "use SPIRE SVID with cert file",
			setupConfig: func(config *MetricsConfig) {
				certFile, keyFile := createTestCertAndKey(t)
				config.FileConfig.Prometheus.TLS = &TLSConfig{
					UseSPIRESVID: true,
					CertFile:     certFile,
					KeyFile:      keyFile,
				}
				config.GetX509SVID = func() (*x509svid.SVID, error) {
					return serverSVID, nil
				}
			},
			errorMsgContains: "cert_file and key_file cannot be configured when use_spire_svid is enabled",
		},
		{
			name: "missing key pair without SPIRE SVID",
			setupConfig: func(config *MetricsConfig) {
				config.FileConfig.Prometheus.TLS = &TLSConfig{}
			},
			errorMsgContains: "cert_file and key_file must both be configured unless use_spire_svid is enabled",
		},
		{
			name: "authorized SPIFFE IDs with client CA file",
			setupConfig: func(config *MetricsConfig) {
				certFile, keyFile := createTestCertAndKey(t)
				caFile := createTestCA(t)
				config.FileConfig.Prometheus.TLS = &TLSConfig{
					CertFile:            certFile,
					KeyFile:             keyFile,
					ClientCAFile:        caFile,
					AuthorizedSPIFFEIDs: []string{"spiffe://example.org/prometheus"},
				}
			},
			errorMsgContains: "client_ca_file cannot be configured with authorized_spiffe_ids",
		},
		{
			name: "invalid authorized SPIFFE ID",
			setupConfig: func(config *MetricsConfig) {
				certFile, keyFile := createTestCertAndKey(t)
				config.FileConfig.Prometheus.TLS = &TLSConfig{
					CertFile:            certFile,
					KeyFile:             keyFile,
					AuthorizedSPIFFEIDs: []string{"not-a-spiffe-id"},
				}
				config.GetX509BundleAuthorities = func(td spiffeid.TrustDomain) ([]*x509.Certificate, error) {
					return serverCA.X509Authorities(), nil
				}
			},
			errorMsgContains: `invalid authorized SPIFFE ID "not-a-spiffe-id"`,
		},
		{
			name: "use SPIRE SVID without SVID source",
			setupConfig: func(config *MetricsConfig) {
				config.FileConfig.Prometheus.TLS = &TLSConfig{
					UseSPIRESVID: true,
				}
			},
			errorMsgContains: "use_spire_svid requires access to the current SPIRE SVID",
		},
		{
			name: "authorized SPIFFE IDs without bundle source",
			setupConfig: func(config *MetricsConfig) {
				certFile, keyFile := createTestCertAndKey(t)
				config.FileConfig.Prometheus.TLS = &TLSConfig{
					CertFile:            certFile,
					KeyFile:             keyFile,
					AuthorizedSPIFFEIDs: []string{"spiffe://example.org/prometheus"},
				}
			},
			errorMsgContains: "authorized_spiffe_ids requires access to SPIRE trust bundles",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testPrometheusConfig()
			tt.setupConfig(config)

			runner, err := newTestPrometheusRunner(config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorMsgContains)
			if runner != nil {
				assert.Nil(t, runner.(*prometheusRunner).server.TLSConfig)
			}
		})
	}
}

// createTestCertAndKey creates a temporary self-signed certificate and private key file
// and returns the paths to both files
func createTestCertAndKey(t *testing.T) (string, string) {
	// Generate a private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	// Write to temporary files
	certFile := createTempFile(t, certPEM)
	keyFile := createTempFile(t, keyPEM)

	return certFile, keyFile
}

// createTestCA creates a temporary CA certificate file and returns its path
func createTestCA(t *testing.T) string {
	// Generate a private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CA certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed CA certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Write to temporary file
	return createTempFile(t, certPEM)
}

// createTempFile creates a temporary file with the given content and returns it's path
func createTempFile(t *testing.T, content []byte) string {
	tmpDir := t.TempDir()
	tmpFile, err := os.CreateTemp(tmpDir, "test-*")
	require.NoError(t, err)
	tmpFilePath := tmpFile.Name()
	err = os.WriteFile(tmpFilePath, content, 0600)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)
	return tmpFilePath
}

func rawCerts(certs []*x509.Certificate) [][]byte {
	raw := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		raw = append(raw, cert.Raw)
	}
	return raw
}
