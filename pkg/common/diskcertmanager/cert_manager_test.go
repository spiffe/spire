package diskcertmanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

const testFileSyncInterval = time.Second

type testPaths struct {
	certPath string
	keyPath  string
}

type testCert struct {
	certPEM []byte
	keyPEM  []byte
}

func TestNew(t *testing.T) {
	paths := setupTestPaths(t)
	validCert := generateTestCert(t, "test", 1)

	tests := []struct {
		name        string
		setupFiles  func()
		config      *Config
		expectError string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: "missing serving cert file configuration",
		},
		{
			name: "cert file does not exist",
			config: &Config{
				CertFilePath: filepath.Join(filepath.Dir(paths.certPath), "nonexistent.pem"),
				KeyFilePath:  paths.keyPath,
			},
			setupFiles: func() {
				require.NoError(t, os.WriteFile(paths.keyPath, validCert.keyPEM, 0600))
			},
			expectError: "failed to load certificate: open",
		},
		{
			name: "key file does not exist",
			config: &Config{
				CertFilePath: paths.certPath,
				KeyFilePath:  filepath.Join(filepath.Dir(paths.keyPath), "nonexistent.pem"),
			},
			setupFiles: func() {
				require.NoError(t, os.WriteFile(paths.certPath, validCert.certPEM, 0600))
			},
			expectError: "failed to load certificate: open",
		},
		{
			name: "invalid cert file",
			config: &Config{
				CertFilePath: paths.certPath,
				KeyFilePath:  paths.keyPath,
			},
			setupFiles: func() {
				require.NoError(t, os.WriteFile(paths.certPath, []byte("invalid"), 0600))
				require.NoError(t, os.WriteFile(paths.keyPath, validCert.keyPEM, 0600))
			},
			expectError: "failed to load certificate: tls: failed to find any PEM data",
		},
		{
			name: "invalid key file",
			config: &Config{
				CertFilePath: paths.certPath,
				KeyFilePath:  paths.keyPath,
			},
			setupFiles: func() {
				require.NoError(t, os.WriteFile(paths.certPath, validCert.certPEM, 0600))
				require.NoError(t, os.WriteFile(paths.keyPath, []byte("invalid"), 0600))
			},
			expectError: "failed to load certificate: tls: failed to find any PEM data",
		},
		{
			name: "success",
			config: &Config{
				CertFilePath: paths.certPath,
				KeyFilePath:  paths.keyPath,
			},
			setupFiles: func() {
				require.NoError(t, os.WriteFile(paths.certPath, validCert.certPEM, 0600))
				require.NoError(t, os.WriteFile(paths.keyPath, validCert.keyPEM, 0600))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Remove(paths.certPath)
			os.Remove(paths.keyPath)

			if tt.setupFiles != nil {
				tt.setupFiles()
			}

			logger, _ := test.NewNullLogger()
			dm, err := New(tt.config, nil, logger)

			if tt.expectError != "" {
				require.ErrorContains(t, err, tt.expectError)
				require.Nil(t, dm)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, dm)

			tlsConfig := dm.GetTLSConfig()
			cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
			require.NoError(t, err)
			require.NotNil(t, cert)
		})
	}
}

func TestSyncCertificateFiles(t *testing.T) {
	paths := setupTestPaths(t)

	cert1 := generateTestCert(t, "cert1", 1)
	cert2 := generateTestCert(t, "cert2", 2)

	writeFilesWithModTime := func(certData, keyData []byte, modTime time.Time) {
		require.NoError(t, os.WriteFile(paths.certPath, certData, 0600))
		require.NoError(t, os.WriteFile(paths.keyPath, keyData, 0600))
		require.NoError(t, os.Chtimes(paths.certPath, modTime, modTime))
		require.NoError(t, os.Chtimes(paths.keyPath, modTime, modTime))
	}

	tests := []struct {
		name           string
		setup          func(dm *DiskCertManager)
		expectCertCN   string
		expectLogError bool
	}{
		{
			name: "no ModTime change - no reload",
			setup: func(dm *DiskCertManager) {
				// Files already have cert1 with ModTime T1, no changes
			},
			expectCertCN: "cert1",
		},
		{
			name: "ModTime changed - successful reload",
			setup: func(dm *DiskCertManager) {
				// Update files to cert2 with newer ModTime
				writeFilesWithModTime(cert2.certPEM, cert2.keyPEM, time.Now().Add(time.Hour))
			},
			expectCertCN: "cert2",
		},
		{
			name: "ModTime changed - invalid cert - keeps old cert",
			setup: func(dm *DiskCertManager) {
				invalidCert := []byte("invalid")
				writeFilesWithModTime(invalidCert, cert2.keyPEM, time.Now().Add(2*time.Hour))
			},
			expectCertCN:   "cert1", // Should keep the old valid cert
			expectLogError: true,
		},
		{
			name: "ModTime changed - invalid key - keeps old cert",
			setup: func(dm *DiskCertManager) {
				invalidKey := []byte("invalid")
				writeFilesWithModTime(cert2.certPEM, invalidKey, time.Now().Add(3*time.Hour))
			},
			expectCertCN:   "cert1",
			expectLogError: true,
		},
		{
			name: "file deleted - logs error, keeps old cert",
			setup: func(dm *DiskCertManager) {
				os.Remove(paths.certPath)
			},
			expectCertCN:   "cert1",
			expectLogError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup initial state with cert1
			baseTime := time.Now()
			writeFilesWithModTime(cert1.certPEM, cert1.keyPEM, baseTime)

			logger, logHook := test.NewNullLogger()
			dm, err := New(&Config{
				CertFilePath: paths.certPath,
				KeyFilePath:  paths.keyPath,
			}, nil, logger)
			require.NoError(t, err)

			logHook.Reset()
			tt.setup(dm)

			dm.syncCertificateFiles()

			cert, err := dm.getCertificate(nil)
			require.NoError(t, err)
			require.NotNil(t, cert.Leaf)
			require.Equal(t, tt.expectCertCN, cert.Leaf.Subject.CommonName)

			if tt.expectLogError {
				require.NotEmpty(t, logHook.AllEntries())
				hasError := false
				for _, entry := range logHook.AllEntries() {
					if entry.Level.String() == "error" {
						hasError = true
						break
					}
				}
				require.True(t, hasError, "expected error log but found none")
			}
		})
	}
}

func TestWatchFileChanges(t *testing.T) {
	paths := setupTestPaths(t)
	cert := generateTestCert(t, "test", 1)

	require.NoError(t, os.WriteFile(paths.certPath, cert.certPEM, 0600))
	require.NoError(t, os.WriteFile(paths.keyPath, cert.keyPEM, 0600))

	logger, logHook := test.NewNullLogger()
	clk := clock.NewMock(t)

	dm, err := New(&Config{
		CertFilePath:     paths.certPath,
		KeyFilePath:      paths.keyPath,
		FileSyncInterval: testFileSyncInterval,
	}, clk, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go dm.WatchFileChanges(ctx)

	clk.WaitForTicker(time.Second, "waiting for file watcher ticker")

	t.Run("ticker fires and calls sync", func(t *testing.T) {
		logHook.Reset()

		clk.Add(testFileSyncInterval)

		// Give goroutine time to process
		require.Eventually(t, func() bool {
			return len(logHook.AllEntries()) > 0
		}, time.Second, 10*time.Millisecond)
	})

	t.Run("stops when context cancelled", func(t *testing.T) {
		logHook.Reset()
		cancel()

		require.Eventually(t, func() bool {
			for _, entry := range logHook.AllEntries() {
				if entry.Message == "Stopping file watcher" {
					return true
				}
			}
			return false
		}, time.Second, 10*time.Millisecond)
	})
}

func generateTestCert(t *testing.T, commonName string, serialNumber int64) testCert {
	key := testkey.MustEC256()
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		NotAfter:     time.Now().Add(time.Hour),
		Subject:      pkix.Name{CommonName: commonName},
	}
	certDER, err := x509util.CreateCertificate(certTmpl, certTmpl, key.Public(), key)
	require.NoError(t, err)

	return testCert{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER.Raw}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

func setupTestPaths(t *testing.T) testPaths {
	tmpDir := t.TempDir()
	return testPaths{
		certPath: filepath.Join(tmpDir, "cert.pem"),
		keyPath:  filepath.Join(tmpDir, "key.pem"),
	}
}
