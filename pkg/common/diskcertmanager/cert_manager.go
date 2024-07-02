package diskcertmanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
)

// DiskCertManager is a certificate manager that loads certificates from disk, and watches for changes.
type DiskCertManager struct {
	certFilePath     string
	keyFilePath      string
	certLastModified time.Time
	keyLastModified  time.Time
	fileSyncInterval time.Duration
	certMtx          sync.RWMutex
	cert             *tls.Certificate
	clk              clock.Clock
	log              logrus.FieldLogger
}

type Config struct {
	CertFilePath     string
	KeyFilePath      string
	FileSyncInterval time.Duration
}

func New(config *Config, clk clock.Clock, log logrus.FieldLogger) (*DiskCertManager, error) {
	if config == nil {
		return nil, errors.New("missing serving cert file configuration")
	}

	if clk == nil {
		clk = clock.New()
	}

	dm := &DiskCertManager{
		certFilePath:     config.CertFilePath,
		keyFilePath:      config.KeyFilePath,
		fileSyncInterval: config.FileSyncInterval,
		log:              log,
		clk:              clk,
	}

	if err := dm.loadCert(); err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	return dm, nil
}

// TLSConfig returns a TLS configuration that uses the provided certificate stored on disk.
func (m *DiskCertManager) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.getCertificate,
		NextProtos: []string{
			"h2", "http/1.1", // enable HTTP/2
		},
		MinVersion: tls.VersionTLS12,
	}
}

// getCertificate is called by the TLS stack when a new TLS connection is established.
func (m *DiskCertManager) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.certMtx.RLock()
	defer m.certMtx.RUnlock()
	cert := m.cert

	return cert, nil
}

// WatchFileChanges starts a file watcher to watch for changes to the cert and key files.
func (m *DiskCertManager) WatchFileChanges(ctx context.Context) {
	m.log.WithField("interval", m.fileSyncInterval).Info("Started watching certificate files")
	ticker := m.clk.Ticker(m.fileSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.log.Info("Stopping file watcher")
			return
		case <-ticker.C:
			m.syncCertificateFiles()
		}
	}
}

// syncCertificateFiles checks if the cert and key files have been modified, and reloads the certificate if necessary.
func (m *DiskCertManager) syncCertificateFiles() {
	certFileInfo, keyFileInfo, err := m.getFilesInfo()
	if err != nil {
		return
	}

	if certFileInfo.ModTime() != m.certLastModified || keyFileInfo.ModTime() != m.keyLastModified {
		m.log.Info("File change detected, reloading certificate and key...")

		if err := m.loadCert(); err != nil {
			m.log.Errorf("Failed to load certificate: %v", err)
		} else {
			m.certLastModified = certFileInfo.ModTime()
			m.keyLastModified = keyFileInfo.ModTime()
			m.log.Info("Loaded provided certificate with success")
		}
	}
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

// getFilesInfo returns the file info of the cert and key files, or error if the files are unreadable or do not exist.
func (m *DiskCertManager) getFilesInfo() (os.FileInfo, os.FileInfo, error) {
	certFileInfo, err := m.getFileInfo(m.certFilePath)
	if err != nil {
		return nil, nil, err
	}

	keyFileInfo, err := m.getFileInfo(m.keyFilePath)
	if err != nil {
		return nil, nil, err
	}

	return certFileInfo, keyFileInfo, nil
}

// getFileInfo returns the file info of the given path, or error if the file is unreadable or does not exist.
func (m *DiskCertManager) getFileInfo(path string) (os.FileInfo, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		errFs := new(fs.PathError)
		switch {
		case errors.Is(err, fs.ErrNotExist) && errors.As(err, &errFs):
			m.log.Errorf("Failed to get file info, file path %q does not exist anymore; please check if the path is correct", errFs.Path)
		default:
			m.log.Errorf("Failed to get file info: %v", err)
		}
		return nil, err
	}

	return fileInfo, nil
}
