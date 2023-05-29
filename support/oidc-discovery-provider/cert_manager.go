package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/idna"
)

var (
	invalidCertLogInterval       = 1 * time.Minute
	parentDirNotFoundLogInterval = 1 * time.Minute
)

// DiskCertManager is a certificate manager that loads certificates from disk, and watches for changes.
type DiskCertManager struct {
	certFilePath                   string
	keyFilePath                    string
	invalidCertLogConfiguredTicker *time.Ticker
	invalidCertConfiguredErr       error
	cert                           *tls.Certificate
	certMtx                        sync.RWMutex
	log                            logrus.FieldLogger
}

func NewDiskCertManager(config *Config, log logrus.FieldLogger) (*DiskCertManager, error) {
	ticker := time.NewTicker(invalidCertLogInterval)
	ticker.Stop()
	dm := &DiskCertManager{
		certFilePath:                   config.ServingCertFile.CertFilePath,
		keyFilePath:                    config.ServingCertFile.KeyFilePath,
		log:                            log,
		invalidCertLogConfiguredTicker: ticker,
	}

	if err := dm.loadCert(); err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	if err := dm.watchFileChanges(); err != nil {
		return nil, err
	}

	go dm.startInvalidCertLog()

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

	if cert.Leaf.Subject.CommonName != name {
		return nil, errors.New("server name mismatch")
	}

	return cert, nil
}

// watchFileChanges starts a file watcher to watch for changes to the cert and key files.
func (m *DiskCertManager) watchFileChanges() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	err = watcher.Add(path.Dir(m.certFilePath))
	if err != nil {
		watcher.Close()
		return fmt.Errorf("failed to add cert file path to file watcher: %w", err)
	}

	err = watcher.Add(path.Dir(m.keyFilePath))
	if err != nil {
		watcher.Close()
		return fmt.Errorf("failed to add key file path to file watcher: %w", err)
	}

	go m.watcherLoop(watcher)

	return nil
}

// watcherLoop is the main loop of the file watcher.
func (m *DiskCertManager) watcherLoop(watcher *fsnotify.Watcher) {
	defer watcher.Close()

	certParent := filepath.Dir(m.certFilePath)
	keyParent := filepath.Dir(m.keyFilePath)
	// A single "write action" initiated by the user may show up as one or multiple
	// writes, depending on when the system syncs things to disk. Here we use a timer
	// to wait for a short period of time for new events to come in, and then reload.
	waitFor := 100 * time.Millisecond
	timer := new(time.Timer)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				m.log.Warn("File watcher stopped watching for changes")
				return
			}

			// If the parent directory of the cert or key file is removed, start watcher sync loop
			if event.Name == certParent || event.Name == keyParent {
				if event.Has(fsnotify.Remove) {
					go m.syncWatcher(event.Name, watcher)
				}
			}

			// Skip if the event is not for the cert or key file
			if event.Name != m.certFilePath && event.Name != m.keyFilePath {
				continue
			}

			switch {
			case event.Has(fsnotify.Write) || event.Has(fsnotify.Chmod):
			case event.Has(fsnotify.Create):
				m.log.Infof("File %q created, the discovery provider started to watch for changes again", event.Name)
			case event.Has(fsnotify.Remove):
				m.log.Warnf("File %q was removed from the file system, please add it again so the discovery provider can detect future changes", event.Name)
				continue
			default:
				continue
			}

			timer = time.AfterFunc(math.MaxInt64, func() { m.processFileChangeEvent(event) })
			timer.Stop()

			// Reset the timer for this path, so it will start from 100ms again.
			timer.Reset(waitFor)

		case err, ok := <-watcher.Errors:
			if !ok {
				m.log.Warn("File watcher stopped watching for changes")
				return
			}
			m.log.Errorf("File watcher error: %v", err)
		}
	}
}

// processFileChangeEvent is called when a file change event is detected.
func (m *DiskCertManager) processFileChangeEvent(_ fsnotify.Event) {
	m.log.Info("File change detected, reloading certificate and key...")
	if err := m.loadCert(); err != nil {
		m.invalidCertConfiguredErr = err
		m.invalidCertLogConfiguredTicker.Reset(invalidCertLogInterval)
	} else {
		m.invalidCertConfiguredErr = nil
		m.invalidCertLogConfiguredTicker.Stop()
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

	m.log.Info("Loaded provided certificate with success")
	return nil
}

// startInvalidCertLog starts a goroutine to log invalid certificate errors.
func (m *DiskCertManager) startInvalidCertLog() {
	go func() {
		for range m.invalidCertLogConfiguredTicker.C {
			err, errFs := m.invalidCertConfiguredErr, new(fs.PathError)
			switch {
			case errors.Is(err, fs.ErrNotExist) && errors.As(err, &errFs):
				m.log.Errorf("Failed to load certificate, file path %q does not exist anymore, please check if the path is correct", errFs.Path)
			case errors.Is(err, fs.ErrPermission) && errors.As(err, &errFs):
				m.log.Errorf("Failed to load certificate, file path %q is unreadable, please ensure it has correct permissions", errFs.Path)
			default:
				m.log.Errorf("Failed to load certificate: %v", err)
			}
		}
	}()
}

// syncWatcher is called when the parent directory of the cert or key file is removed.
// Watchers are added to the parent directory of the cert and key file to detect future changes,
// when the parent dir is removed from the filesystem the watcher is also removed. So we need to
// add the watcher again to the parent dir when it is recreated.
func (m *DiskCertManager) syncWatcher(dirPath string, watcher *fsnotify.Watcher) {
	ticker := time.NewTicker(parentDirNotFoundLogInterval)

	for range ticker.C {
		certExist, keyExist := false, false

		if _, err := os.Stat(m.certFilePath); err == nil {
			certExist = true
		}

		if _, err := os.Stat(m.keyFilePath); err == nil {
			keyExist = true
		}

		if certExist && keyExist {
			err := watcher.Add(path.Dir(dirPath))

			if err != nil {
				m.log.Errorf("Failed to add %q to file watcher: %v", dirPath, err)
				continue
			}

			if err := m.loadCert(); err != nil {
				m.invalidCertConfiguredErr = err
				m.invalidCertLogConfiguredTicker.Reset(invalidCertLogInterval)
			} else {
				m.invalidCertConfiguredErr = nil
				m.invalidCertLogConfiguredTicker.Stop()
			}

			ticker.Stop()
			return
		}
		m.log.Errorf("Parent directory %q was not found, waiting for it to be created", dirPath)
	}
}
