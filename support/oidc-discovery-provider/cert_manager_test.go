package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
)

var logger, logHook = test.NewNullLogger()

func TestMain(m *testing.M) {
	code := m.Run()

	for _, entry := range logHook.AllEntries() {
		println(entry.Message)
	}
	os.Exit(code)
}

func TestTLSConfig(t *testing.T) {
	fileSyncInterval = 10 * time.Millisecond

	oidcServerKey := testkey.MustEC256()
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

	oidcServerKeyNew := testkey.MustEC256()
	oidcServerKeyNewDer, err := x509.MarshalECPrivateKey(oidcServerKeyNew)
	require.NoError(t, err)

	oidcServerCertUpdated2, err := x509util.CreateCertificate(certTmpl, certTmpl, oidcServerKeyNew.Public(), oidcServerKeyNew)
	require.NoError(t, err)

	certTmpl.Subject.Country = []string{"US"}

	oidcServerCertUpdated3, err := x509util.CreateCertificate(certTmpl, certTmpl, oidcServerKey.Public(), oidcServerKeyNew)
	require.NoError(t, err)

	tmpDir := t.TempDir()

	err = writeFile(tmpDir+keyFilePath, oidcServerKeyPem)
	require.NoError(t, err)
	err = writeFile(tmpDir+certFilePath, oidcServerCertPem)
	require.NoError(t, err)
	err = writeFile(tmpDir+"/oidcServerKeyInvalid.pem", []byte{1})
	require.NoError(t, err)
	err = writeFile(tmpDir+"/oidcServerCertInvalid.pem", []byte{1})
	require.NoError(t, err)
	err = writeFile(tmpDir+"/oidcServerKeyUnreadable.pem", []byte{1})
	require.NoError(t, err)
	err = makeFileUnreadable(tmpDir + "/oidcServerKeyUnreadable.pem")
	require.NoError(t, err)
	err = writeFile(tmpDir+"/oidcServerCertUnreadable.pem", []byte{1})
	require.NoError(t, err)
	err = makeFileUnreadable(tmpDir + "/oidcServerCertUnreadable.pem")
	require.NoError(t, err)

	chInfo := &tls.ClientHelloInfo{
		ServerName: "oidc-provider-discovery.example.com",
	}

	certManager, err := NewDiskCertManager(&Config{ServingCertFile: &ServingCertFileConfig{
		CertFilePath: tmpDir + certFilePath,
		KeyFilePath:  tmpDir + keyFilePath,
	}}, logger)
	require.NoError(t, err)

	tlsConfig := certManager.TLSConfig()

	t.Run("error when provided cert path do not exist", func(t *testing.T) {
		_, err := NewDiskCertManager(&Config{ServingCertFile: &ServingCertFileConfig{
			CertFilePath: tmpDir + "/nonexistent_cert.pem",
			KeyFilePath:  tmpDir + "/oidcServerKey.pem",
		}}, logger)

		require.EqualError(t, err, "failed to load certificate: open "+tmpDir+"/nonexistent_cert.pem: "+fileDontExistMessage)
	})

	t.Run("error when provided key path do not exist", func(t *testing.T) {
		_, err := NewDiskCertManager(&Config{ServingCertFile: &ServingCertFileConfig{
			CertFilePath: tmpDir + certFilePath,
			KeyFilePath:  tmpDir + "/nonexistent_key.pem",
		}}, logger)

		require.EqualError(t, err, "failed to load certificate: open "+tmpDir+"/nonexistent_key.pem: "+fileDontExistMessage)
	})

	t.Run("error when provided cert path is unreadable", func(t *testing.T) {
		_, err := NewDiskCertManager(&Config{ServingCertFile: &ServingCertFileConfig{
			CertFilePath: tmpDir + "/oidcServerCertUnreadable.pem",
			KeyFilePath:  tmpDir + "/oidcServerKey.pem",
		}}, logger)

		require.EqualError(t, err, "failed to load certificate: open "+tmpDir+"/oidcServerCertUnreadable.pem: "+filePermissionDeniedMessage)
	})

	t.Run("error when provided key path is unreadable", func(t *testing.T) {
		_, err := NewDiskCertManager(&Config{ServingCertFile: &ServingCertFileConfig{
			CertFilePath: tmpDir + certFilePath,
			KeyFilePath:  tmpDir + "/oidcServerKeyUnreadable.pem",
		}}, logger)

		require.EqualError(t, err, "failed to load certificate: open "+tmpDir+"/oidcServerKeyUnreadable.pem: "+filePermissionDeniedMessage)
	})

	t.Run("error when provided cert is invalid", func(t *testing.T) {
		_, err := NewDiskCertManager(&Config{ServingCertFile: &ServingCertFileConfig{
			CertFilePath: tmpDir + "/oidcServerCertInvalid.pem",
			KeyFilePath:  tmpDir + "/oidcServerKey.pem",
		}}, logger)

		require.EqualError(t, err, "failed to load certificate: tls: failed to find any PEM data in certificate input")
	})

	t.Run("error when provided key is invalid", func(t *testing.T) {
		_, err := NewDiskCertManager(&Config{ServingCertFile: &ServingCertFileConfig{
			CertFilePath: tmpDir + certFilePath,
			KeyFilePath:  tmpDir + "/oidcServerKeyInvalid.pem",
		}}, logger)

		require.EqualError(t, err, "failed to load certificate: tls: failed to find any PEM data in key input")
	})

	t.Run("error when client misses server name", func(t *testing.T) {
		_, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
		require.EqualError(t, err, "missing server name")
	})

	t.Run("error when client send server name with invalid character", func(t *testing.T) {
		_, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{
			ServerName: "example.com:8080",
		})
		require.EqualError(t, err, "server name contains invalid character")
	})

	t.Run("error when client send server name with invalid component count", func(t *testing.T) {
		_, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{
			ServerName: "example",
		})
		require.EqualError(t, err, "server name component count invalid")
	})

	t.Run("error when client send wrong server name", func(t *testing.T) {
		_, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{
			ServerName: "example.com",
		})
		require.EqualError(t, err, `server name mismatch: x509: certificate is not valid for any names, but wanted to match example.com`)
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
		err = writeFile(tmpDir+certFilePath, oidcServerCertUpdatedPem)
		require.NoError(t, err)

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
		}, 1*time.Second, 101*time.Millisecond, "Failed to assert updated certificate")
	})

	t.Run("success watching to key file changes", func(t *testing.T) {
		err = writeFile(tmpDir+keyFilePath, pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: oidcServerKeyNewDer,
		}))
		require.NoError(t, err)

		err = writeFile(tmpDir+certFilePath, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: oidcServerCertUpdated2.Raw,
		}))
		require.NoError(t, err)

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
		}, 1*time.Second, 101*time.Millisecond, "Failed to assert updated certificate")
	})

	t.Run("update cert file with an invalid cert start error log loop", func(t *testing.T) {
		err = writeFile(tmpDir+certFilePath, []byte("invalid-cert"))
		require.NoError(t, err)

		errLogs := map[time.Time]struct{}{}

		// Assert error logs that will keep triggering until the cert is valid again
		require.Eventuallyf(t, func() bool {
			for _, entry := range logHook.AllEntries() {
				if entry.Level == logrus.ErrorLevel && strings.Contains(entry.Message, "Failed to load certificate: tls: failed to find any PEM data in certificate input") {
					errLogs[entry.Time] = struct{}{}
				}
			}
			return len(errLogs) >= 5
		}, 500*time.Millisecond, 10*time.Millisecond, "Failed to assert error logs")

		// New cert is not loaded because it is invalid.
		cert, err := tlsConfig.GetCertificate(chInfo)
		require.NoError(t, err)
		require.Len(t, cert.Certificate, 1)
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		require.Equal(t, oidcServerCertUpdated2, x509Cert)
	})

	t.Run("update key file with an invalid key start error log loop", func(t *testing.T) {
		err = writeFile(tmpDir+certFilePath, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: oidcServerCertUpdated2.Raw,
		}))
		require.NoError(t, err)

		err = writeFile(tmpDir+keyFilePath, []byte("invalid-key"))
		require.NoError(t, err)

		// Assert error logs that will keep triggering until the cert is valid again.
		errLogs := map[time.Time]struct{}{}

		require.Eventuallyf(t, func() bool {
			for _, entry := range logHook.AllEntries() {
				if entry.Level == logrus.ErrorLevel && strings.Contains(entry.Message, "Failed to load certificate: tls: failed to find any PEM data in key input") {
					errLogs[entry.Time] = struct{}{}
				}
			}
			return len(errLogs) >= 5
		}, 500*time.Millisecond, 10*time.Millisecond, "Failed to assert error logs")

		// New cert is not loaded because it is invalid.
		cert, err := tlsConfig.GetCertificate(chInfo)
		require.NoError(t, err)
		require.Len(t, cert.Certificate, 1)
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		require.Equal(t, oidcServerCertUpdated2, x509Cert)
	})

	t.Run("stop logging error when update to valid certificate and key", func(t *testing.T) {
		err = writeFile(tmpDir+keyFilePath, oidcServerKeyPem)
		require.NoError(t, err)
		err = writeFile(tmpDir+certFilePath, oidcServerCertPem)
		require.NoError(t, err)

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
		}, 1*time.Second, 100*time.Millisecond, "Failed to assert updated certificate")
	})

	t.Run("delete cert files start error log loop", func(t *testing.T) {
		err = removeFile(tmpDir + keyFilePath)
		require.NoError(t, err)

		// Assert error logs that will keep triggering until the key is created again.
		errLogs := map[time.Time]struct{}{}
		require.Eventuallyf(t, func() bool {
			for _, entry := range logHook.AllEntries() {
				if entry.Level == logrus.ErrorLevel && strings.Contains(entry.Message, fmt.Sprintf("Failed to get file info, file path %q does not exist anymore; please check if the path is correct", tmpDir+keyFilePath)) {
					errLogs[entry.Time] = struct{}{}
				}
			}
			return len(errLogs) >= 5
		}, 500*time.Millisecond, 10*time.Millisecond, "Failed to assert non-existing key error logs")

		err = removeFile(tmpDir + certFilePath)
		require.NoError(t, err)

		// Assert error logs that will keep triggering until the cert is created again.
		errLogs = map[time.Time]struct{}{}
		require.Eventuallyf(t, func() bool {
			for _, entry := range logHook.AllEntries() {
				if entry.Level == logrus.ErrorLevel && strings.Contains(entry.Message, fmt.Sprintf("Failed to get file info, file path %q does not exist anymore; please check if the path is correct", tmpDir+certFilePath)) {
					errLogs[entry.Time] = struct{}{}
				}
			}
			return len(errLogs) >= 5
		}, 500*time.Millisecond, 10*time.Millisecond, "Failed to assert non-existing cert error logs")

		err = writeFile(tmpDir+keyFilePath, oidcServerKeyPem)
		require.NoError(t, err)

		err = writeFile(tmpDir+certFilePath, oidcServerCertPem)
		require.NoError(t, err)

		require.Eventuallyf(t, func() bool {
			return logHook.LastEntry().Message == "Loaded provided certificate with success"
		}, 500*time.Millisecond, 10*time.Millisecond, "Failed to assert updated certificate")

		cert, err := tlsConfig.GetCertificate(chInfo)
		require.NoError(t, err)
		require.Len(t, cert.Certificate, 1)
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		require.Equal(t, oidcServerCert, x509Cert)
	})

	t.Run("change cert and key file permissions will start error log loop", func(t *testing.T) {
		//	make cert file not readable
		err = makeFileUnreadable(tmpDir + certFilePath)
		require.NoError(t, err)

		err = writeFile(tmpDir+certFilePath, oidcServerCertPem)
		require.NoError(t, err)

		// Assert error logs that will keep triggering until the cert permission is valid again.
		errLogs := map[time.Time]struct{}{}
		require.Eventuallyf(t, func() bool {
			for _, entry := range logHook.AllEntries() {
				if entry.Level == logrus.ErrorLevel && strings.Contains(entry.Message, fmt.Sprintf("Failed to load certificate: open %s: %s", tmpDir+certFilePath, filePermissionDeniedMessage)) {
					errLogs[entry.Time] = struct{}{}
				}
			}
			return len(errLogs) >= 5
		}, 500*time.Millisecond, 10*time.Millisecond, "Failed to assert file permission error logs")

		oidcServerCertUpdated3Pem := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: oidcServerCertUpdated3.Raw,
		})

		//	make cert file readable again
		err = makeFileReadable(tmpDir+certFilePath, oidcServerCertUpdated3Pem)
		require.NoError(t, err)

		err = makeFileUnreadable(tmpDir + keyFilePath)
		require.NoError(t, err)

		errLogs = map[time.Time]struct{}{}
		require.Eventuallyf(t, func() bool {
			for _, entry := range logHook.AllEntries() {
				if entry.Level == logrus.ErrorLevel && strings.Contains(entry.Message, fmt.Sprintf("Failed to load certificate: open %s: %s", tmpDir+keyFilePath, filePermissionDeniedMessage)) {
					errLogs[entry.Time] = struct{}{}
				}
			}
			return len(errLogs) >= 5
		}, 500*time.Millisecond, 10*time.Millisecond, "Failed to assert file permission error logs")

		//	make cert file readable again
		err = makeFileReadable(tmpDir+keyFilePath, oidcServerKeyPem)
		require.NoError(t, err)

		// New cert can now be loaded.
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
			return reflect.DeepEqual(oidcServerCertUpdated3, x509Cert)
		}, 1*time.Second, 100*time.Millisecond, "Failed to assert updated certificate")
	})
}
