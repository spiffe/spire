package diskcertmanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

var (
	oidcServerKey    = testkey.MustEC256()
	oidcServerKeyNew = testkey.MustEC256()
)

const (
	testFileSyncInterval  = 10 * time.Millisecond
	testTickerIterations  = 5
	testTotalSyncDuration = testFileSyncInterval * testTickerIterations // 50ms = 5 ticks of 10ms
)

func TestTLSConfig(t *testing.T) {
	logger, logHook := test.NewNullLogger()

	clk := clock.NewMock(t)

	oidcServerKeyDer, err := x509.MarshalECPrivateKey(oidcServerKey)
	require.NoError(t, err)

	certTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotAfter:     time.Now().Add(time.Hour),
		Subject: pkix.Name{
			Country:    []string{"BR"},
			CommonName: "oidc-provider-discovery.example.com",
		},
	}
	oidcServerCert, err := x509util.CreateCertificate(certTmpl, certTmpl, oidcServerKey.Public(), oidcServerKey)
	require.NoError(t, err)
	require.NotNilf(t, oidcServerCert, "oidcServerCert is nil")

	oidcServerKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: oidcServerKeyDer,
	})

	oidcServerCertPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: oidcServerCert.Raw,
	})

	certTmpl.Subject.Country = []string{"AR"}
	oidcServerCertUpdated1, err := x509util.CreateCertificate(certTmpl, certTmpl, oidcServerKey.Public(), oidcServerKey)
	require.NoError(t, err)

	oidcServerKeyNewDer, err := x509.MarshalECPrivateKey(oidcServerKeyNew)
	require.NoError(t, err)

	oidcServerCertUpdated2, err := x509util.CreateCertificate(certTmpl, certTmpl, oidcServerKeyNew.Public(), oidcServerKeyNew)
	require.NoError(t, err)

	certTmpl.Subject.Country = []string{"US"}

	tmpDir := t.TempDir()
	certFilePath := filepath.Join(tmpDir, "oidcServerCert.pem")
	keyFilePath := filepath.Join(tmpDir, "oidcServerKey.pem")
	invalidCertFilePath := filepath.Join(tmpDir, "oidcServerCertInvalid.pem")
	invalidKeyFilePath := filepath.Join(tmpDir, "oidcServerKeyInvalid.pem")

	writeFile(t, keyFilePath, oidcServerKeyPem)
	writeFile(t, certFilePath, oidcServerCertPem)
	writeFile(t, invalidKeyFilePath, []byte{1})
	writeFile(t, invalidCertFilePath, []byte{1})

	chInfo := &tls.ClientHelloInfo{
		ServerName: "oidc-provider-discovery.example.com",
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	certManager, err := New(&Config{
		CertFilePath:     certFilePath,
		KeyFilePath:      keyFilePath,
		FileSyncInterval: testFileSyncInterval,
	}, clk, logger)
	require.NoError(t, err)

	go func() {
		certManager.WatchFileChanges(ctx)
	}()

	// Wait for the file watcher's ticker to be created before proceeding
	clk.WaitForTicker(time.Second, "waiting for file watcher ticker to be created")

	tlsConfig := certManager.GetTLSConfig()

	t.Run("error when configuration does not contain serving cert file settings", func(t *testing.T) {
		_, err := New(nil, nil, logger)
		require.EqualError(t, err, "missing serving cert file configuration")
	})

	t.Run("error when provided cert path do not exist", func(t *testing.T) {
		_, err := New(&Config{
			CertFilePath: filepath.Join(tmpDir, "nonexistent_cert.pem"),
			KeyFilePath:  keyFilePath,
		}, clk, logger)

		require.ErrorContains(t, err, fmt.Sprintf("failed to load certificate: open %s", filepath.Join(tmpDir, "nonexistent_cert.pem")))
	})

	t.Run("error when provided key path do not exist", func(t *testing.T) {
		_, err := New(&Config{
			CertFilePath: certFilePath,
			KeyFilePath:  filepath.Join(tmpDir, "nonexistent_key.pem"),
		}, clk, logger)

		require.ErrorContains(t, err, fmt.Sprintf("failed to load certificate: open %s", filepath.Join(tmpDir, "nonexistent_key.pem")))
	})

	t.Run("error when provided cert is invalid", func(t *testing.T) {
		_, err := New(&Config{
			CertFilePath: invalidCertFilePath,
			KeyFilePath:  keyFilePath,
		}, clk, logger)

		require.EqualError(t, err, "failed to load certificate: tls: failed to find any PEM data in certificate input")
	})

	t.Run("error when provided key is invalid", func(t *testing.T) {
		_, err := New(&Config{
			CertFilePath: certFilePath,
			KeyFilePath:  invalidKeyFilePath,
		}, clk, logger)

		require.EqualError(t, err, "failed to load certificate: tls: failed to find any PEM data in key input")
	})

	t.Run("success loading initial certificate from disk", func(t *testing.T) {
		cert, err := tlsConfig.GetCertificate(chInfo)
		require.NoError(t, err)
		require.Len(t, cert.Certificate, 1)
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		require.Equal(t, oidcServerCert, x509Cert)
	})

	t.Run("success watching cert file changes", func(t *testing.T) {
		oidcServerCertUpdatedPem := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: oidcServerCertUpdated1.Raw,
		})
		writeFile(t, certFilePath, oidcServerCertUpdatedPem)

		clk.Add(testFileSyncInterval / 2) // Less than sync interval

		// Certificate is not updated yet
		cert, err := tlsConfig.GetCertificate(chInfo)
		require.NoError(t, err)
		require.Len(t, cert.Certificate, 1)
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		require.Equal(t, oidcServerCert, x509Cert)

		clk.Add(testFileSyncInterval)

		// Assert certificate is updated
		require.Eventuallyf(t, func() bool {
			cert, err := tlsConfig.GetCertificate(chInfo)
			if err != nil {
				return false
			}
			require.Len(t, cert.Certificate, 1)
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return false
			}
			return reflect.DeepEqual(oidcServerCertUpdated1, x509Cert)
		}, 10*time.Second, 10*time.Millisecond, "Failed to assert updated certificate")
	})

	t.Run("success watching to key file changes", func(t *testing.T) {
		writeFile(t, keyFilePath, pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: oidcServerKeyNewDer,
		}))

		writeFile(t, certFilePath, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: oidcServerCertUpdated2.Raw,
		}))

		clk.Add(testFileSyncInterval)

		require.Eventuallyf(t, func() bool {
			cert, err := tlsConfig.GetCertificate(chInfo)
			if err != nil {
				return false
			}
			require.Len(t, cert.Certificate, 1)
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return false
			}
			return reflect.DeepEqual(oidcServerCertUpdated2, x509Cert)
		}, 10*time.Second, 10*time.Millisecond, "Failed to assert updated certificate")
	})

	t.Run("update cert file with an invalid cert start error log loop", func(t *testing.T) {
		logHook.Reset()
		writeFile(t, certFilePath, []byte("invalid-cert"))

		clk.Add(testTotalSyncDuration)

		// Assert error logs were triggered (at least 1, at most testTickerIterations)
		// Use Eventually to give the goroutine time to process the clock ticks
		require.Eventually(t, func() bool {
			errLogs := map[time.Time]struct{}{}
			for _, entry := range logHook.AllEntries() {
				if entry.Level == logrus.ErrorLevel && strings.Contains(entry.Message, "Failed to load certificate: tls: failed to find any PEM data in certificate input") {
					errLogs[entry.Time] = struct{}{}
				}
			}
			return len(errLogs) >= 1 && len(errLogs) <= testTickerIterations
		}, time.Second, 10*time.Millisecond, "expected 1-%d error logs", testTickerIterations)

		// New cert is not loaded because it is invalid.
		cert, err := tlsConfig.GetCertificate(chInfo)
		require.NoError(t, err)
		require.Len(t, cert.Certificate, 1)
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		require.Equal(t, oidcServerCertUpdated2, x509Cert)
	})

	t.Run("update key file with an invalid key start error log loop", func(t *testing.T) {
		logHook.Reset()
		writeFile(t, certFilePath, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: oidcServerCertUpdated2.Raw,
		}))

		writeFile(t, keyFilePath, []byte("invalid-key"))

		clk.Add(testTotalSyncDuration)

		// Assert error logs were triggered (at least 1, at most testTickerIterations)
		// Use Eventually to give the goroutine time to process the clock ticks
		require.Eventually(t, func() bool {
			errLogs := map[time.Time]struct{}{}
			for _, entry := range logHook.AllEntries() {
				if entry.Level == logrus.ErrorLevel && strings.Contains(entry.Message, "Failed to load certificate: tls: failed to find any PEM data in key input") {
					errLogs[entry.Time] = struct{}{}
				}
			}
			return len(errLogs) >= 1 && len(errLogs) <= testTickerIterations
		}, time.Second, 10*time.Millisecond, "expected 1-%d error logs", testTickerIterations)

		// New cert is not loaded because it is invalid.
		cert, err := tlsConfig.GetCertificate(chInfo)
		require.NoError(t, err)
		require.Len(t, cert.Certificate, 1)
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		require.Equal(t, oidcServerCertUpdated2, x509Cert)
	})

	t.Run("stop logging error when update to valid certificate and key", func(t *testing.T) {
		writeFile(t, keyFilePath, oidcServerKeyPem)
		writeFile(t, certFilePath, oidcServerCertPem)

		clk.Add(testFileSyncInterval)

		require.Eventuallyf(t, func() bool {
			cert, err := tlsConfig.GetCertificate(chInfo)
			if err != nil {
				return false
			}
			require.Len(t, cert.Certificate, 1)
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return false
			}
			return reflect.DeepEqual(oidcServerCert, x509Cert)
		}, 10*time.Second, 10*time.Millisecond, "Failed to assert updated certificate")
	})

	t.Run("delete cert files start error log loop", func(t *testing.T) {
		logHook.Reset()
		removeFile(t, keyFilePath)

		clk.Add(testTotalSyncDuration)

		// Assert error logs were triggered (at least 1, at most testTickerIterations)
		// Use Eventually to give the goroutine time to process the clock ticks
		require.Eventually(t, func() bool {
			errLogs := map[time.Time]struct{}{}
			for _, entry := range logHook.AllEntries() {
				if entry.Level == logrus.ErrorLevel && strings.Contains(entry.Message, fmt.Sprintf("Failed to get file info, file path %q does not exist anymore; please check if the path is correct", keyFilePath)) {
					errLogs[entry.Time] = struct{}{}
				}
			}
			return len(errLogs) >= 1 && len(errLogs) <= testTickerIterations
		}, time.Second, 10*time.Millisecond, "expected 1-%d error logs", testTickerIterations)

		removeFile(t, certFilePath)
		logHook.Reset()

		clk.Add(testTotalSyncDuration)

		// Assert error logs were triggered (at least 1, at most testTickerIterations)
		// Use Eventually to give the goroutine time to process the clock ticks
		require.Eventually(t, func() bool {
			errLogs := map[time.Time]struct{}{}
			for _, entry := range logHook.AllEntries() {
				if entry.Level == logrus.ErrorLevel && strings.Contains(entry.Message, fmt.Sprintf("Failed to get file info, file path %q does not exist anymore; please check if the path is correct", certFilePath)) {
					errLogs[entry.Time] = struct{}{}
				}
			}
			return len(errLogs) >= 1 && len(errLogs) <= testTickerIterations
		}, time.Second, 10*time.Millisecond, "expected 1-%d error logs", testTickerIterations)

		writeFile(t, keyFilePath, oidcServerKeyPem)

		writeFile(t, certFilePath, oidcServerCertPem)

		clk.Add(testFileSyncInterval)

		require.Eventuallyf(t, func() bool {
			cert, err := tlsConfig.GetCertificate(chInfo)
			require.NoError(t, err)
			require.Len(t, cert.Certificate, 1)
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			require.NoError(t, err)
			require.Equal(t, oidcServerCert, x509Cert)

			return reflect.DeepEqual(oidcServerCert, x509Cert) && logHook.LastEntry().Message == "Loaded provided certificate with success"
		}, 10*time.Second, 10*time.Millisecond, "Failed to assert error logs")
	})

	t.Run("stop file watcher when context is canceled", func(t *testing.T) {
		cancelFn()

		require.Eventuallyf(t, func() bool {
			lastEntry := logHook.LastEntry()
			return lastEntry.Level == logrus.InfoLevel && lastEntry.Message == "Stopping file watcher"
		}, 1*time.Second, 10*time.Millisecond, "Failed to assert file watcher stop log")
	})
}

func writeFile(t *testing.T, name string, data []byte) {
	// Ensure ModTime will be different from previous write by setting it explicitly.
	// This handles filesystems with coarse ModTime resolution (e.g., 1-second granularity).
	newModTime := time.Now()
	info, err := os.Stat(name)
	switch {
	case err == nil:
		newModTime = info.ModTime().Add(time.Second)
	case os.IsNotExist(err):
		// File doesn't exist - use time.Now()
	default:
		require.NoError(t, err, "failed to stat file before writing")
	}

	require.NoError(t, os.WriteFile(name, data, 0600))
	require.NoError(t, os.Chtimes(name, newModTime, newModTime))
}

func removeFile(t *testing.T, name string) {
	err := os.Remove(name)
	require.NoError(t, err)
}
