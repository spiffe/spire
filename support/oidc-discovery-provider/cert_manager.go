package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/idna"
)

var (
	fileSyncInterval = 1 * time.Minute
)

// DiskCertManager is a certificate manager that loads certificates from disk, and watches for changes.
type DiskCertManager struct {
	certFilePath string
	keyFilePath  string
	cert         *tls.Certificate
	certMtx      sync.RWMutex
	log          logrus.FieldLogger
}

func NewDiskCertManager(config *Config, log logrus.FieldLogger) (*DiskCertManager, error) {
	dm := &DiskCertManager{
		certFilePath: config.ServingCertFile.CertFilePath,
		keyFilePath:  config.ServingCertFile.KeyFilePath,
		log:          log,
	}

	if err := dm.loadCert(); err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	go dm.watchFileChanges()

	return dm, nil
}

// TLSConfig returns a TLS configuration that uses the provided certificate stored on disk.
func (m *DiskCertManager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.getCertificate,
		NextProtos: []string{
			"h2", "http/1.1", // enable HTTP/2
		},
		MinVersion: tls.VersionTLS12,
	}
}

// getCertificate is called by the TLS stack when a new TLS connection is established.
func (m *DiskCertManager) getCertificate(chInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := chInfo.ServerName
	if name == "" {
		return nil, errors.New("missing server name")
	}
	if !strings.Contains(strings.Trim(name, "."), ".") {
		return nil, errors.New("server name component count invalid")
	}

	// Note that this conversion is necessary because some server names in the handshakes
	// started by some clients (such as cURL) are not converted to Punycode, which will
	// prevent us from obtaining certificates for them. In addition, we should also treat
	// example.com and EXAMPLE.COM as equivalent and return the same certificate for them.
	// Fortunately, this conversion also helped us deal with this kind of mixedcase problems.
	//
	// Due to the "σςΣ" problem (see https://unicode.org/faq/idn.html#22), we can't use
	// idna.Punycode.ToASCII (or just idna.ToASCII) here.
	name, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return nil, errors.New("server name contains invalid character")
	}

	m.certMtx.RLock()
	defer m.certMtx.RUnlock()
	cert := m.cert

	// Verify that the certificate is valid for the requested server name.
	if name != cert.Leaf.Subject.CommonName {
		if err := cert.Leaf.VerifyHostname(name); err != nil {
			return nil, fmt.Errorf("server name mismatch: %w", err)
		}
	}

	return cert, nil
}

// watchFileChanges starts a file watcher to watch for changes to the cert and key files.
func (m *DiskCertManager) watchFileChanges() {
	ticker := time.NewTicker(fileSyncInterval)
	certLastModified := time.Now()
	keyLastModified := time.Now()
	for range ticker.C {
		if m.hasFileChanges(certLastModified, keyLastModified) {
			m.log.Info("File change detected, reloading certificate and key...")

			if err := m.loadCert(); err != nil {
				m.log.Errorf("Failed to load certificate: %v", err)
			} else {
				m.log.Info("Loaded provided certificate with success")
			}
		}
	}
}

// hasFileChanges checks if the cert and key files have been modified since the last check.
func (m *DiskCertManager) hasFileChanges(certLastModified time.Time, keyLastModified time.Time) bool {
	certFileInfo, err := os.Stat(m.certFilePath)
	if err != nil {
		m.logStatError(err)
		return false
	}

	if certFileInfo.Mode().Perm()&0400 == 0 {
		m.log.Errorf("Failed to load certificate, file path %q is unreadable, please ensure it has correct permissions", m.certFilePath)
		return false
	}

	keyFileInfo, err := os.Stat(m.keyFilePath)
	if err != nil {
		m.logStatError(err)
		return false
	}

	if keyFileInfo.Mode().Perm()&0400 == 0 {
		m.log.Errorf("Failed to load certificate, file path %q is unreadable, please ensure it has correct permissions", m.keyFilePath)
		return false
	}

	if certFileInfo.ModTime() != certLastModified || keyFileInfo.ModTime() != keyLastModified {
		return true
	}

	return false
}

// loadCert read the certificate and key files, and load the x509 certificate to memory.
func (m *DiskCertManager) loadCert() error {
	cert, err := tls.LoadX509KeyPair(m.certFilePath, m.keyFilePath)
	if err != nil {
		return err
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}

	m.certMtx.Lock()
	defer m.certMtx.Unlock()

	m.cert = &cert

	return nil
}

// logStatError logs the error from os.Stat method.
func (m *DiskCertManager) logStatError(err error) {
	errFs := new(fs.PathError)
	switch {
	case errors.Is(err, fs.ErrNotExist) && errors.As(err, &errFs):
		m.log.Errorf("Failed to load certificate, file path %q does not exist anymore, please check if the path is correct", errFs.Path)
	default:
		m.log.Errorf("Failed to load certificate: %v", err)
	}
}
