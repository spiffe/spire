package telemetry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	prommetrics "github.com/hashicorp/go-metrics/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus/hooks/test"
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

func TestNewPrometheusRunnerWithTLS(t *testing.T) {
	certFile, keyFile := generateTestCertFiles(t)

	config := testPrometheusConfig()
	config.FileConfig.Prometheus.TLS = &PrometheusTLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	pr, err := newTestPrometheusRunner(config)
	require.NoError(t, err)
	require.NotNil(t, pr)

	runner := pr.(*prometheusRunner)
	require.NotNil(t, runner.server.TLSConfig)
	assert.Equal(t, 1, len(runner.server.TLSConfig.Certificates))
}

func TestNewPrometheusRunnerWithMTLS(t *testing.T) {
	certFile, keyFile := generateTestCertFiles(t)

	config := testPrometheusConfig()
	config.FileConfig.Prometheus.TLS = &PrometheusTLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   certFile, // reuse the cert as the CA
	}

	pr, err := newTestPrometheusRunner(config)
	require.NoError(t, err)
	require.NotNil(t, pr)

	runner := pr.(*prometheusRunner)
	require.NotNil(t, runner.server.TLSConfig)
	require.NotNil(t, runner.server.TLSConfig.ClientCAs)
}

func TestNewPrometheusRunnerWithTLSInvalidCert(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, []byte("invalid"), 0600))
	require.NoError(t, os.WriteFile(keyFile, []byte("invalid"), 0600))

	config := testPrometheusConfig()
	config.FileConfig.Prometheus.TLS = &PrometheusTLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	_, err := newTestPrometheusRunner(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to build prometheus TLS config")
}

func TestNewPrometheusRunnerWithTLSMissingCAFile(t *testing.T) {
	certFile, keyFile := generateTestCertFiles(t)

	config := testPrometheusConfig()
	config.FileConfig.Prometheus.TLS = &PrometheusTLSConfig{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   "/nonexistent/ca.pem",
	}

	_, err := newTestPrometheusRunner(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to build prometheus TLS config")
}

func generateTestCertFiles(t *testing.T) (certFile, keyFile string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	certFile = filepath.Join(tmpDir, "cert.pem")
	keyFile = filepath.Join(tmpDir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	require.NoError(t, os.WriteFile(certFile, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0600))

	return certFile, keyFile
}
