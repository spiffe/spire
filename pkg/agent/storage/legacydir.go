package storage

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"path"

	"github.com/spiffe/spire/pkg/common/diskutil"
)

func LegacyDir(dir string) Storage {
	return legacyDir{dir: dir}
}

type legacyDir struct {
	dir string
}

func (l legacyDir) LoadBundle() ([]*x509.Certificate, error) {
	bundlePath := l.bundlePath()
	if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
		return nil, ErrNotCached
	}

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("error reading bundle at %s: %w", bundlePath, err)
	}

	bundle, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing bundle at %s: %w", bundlePath, err)
	}
	return bundle, nil
}

func (l legacyDir) StoreBundle(bundle []*x509.Certificate) error {
	// Write all certs to data bytes buffer.
	data := &bytes.Buffer{}
	for _, cert := range bundle {
		data.Write(cert.Raw)
	}

	// Write data to disk.
	return diskutil.AtomicWriteFile(l.bundlePath(), data.Bytes(), 0600)
}

func (l legacyDir) LoadSVID() ([]*x509.Certificate, error) {
	agentSVIDPath := l.agentSVIDPath()
	data, err := os.ReadFile(agentSVIDPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotCached
		}
		return nil, fmt.Errorf("error reading SVID at %s: %w", agentSVIDPath, err)
	}

	certChain, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing SVID at %s: %w", agentSVIDPath, err)
	}
	return certChain, nil
}

func (l legacyDir) StoreSVID(svidChain []*x509.Certificate) error {
	data := &bytes.Buffer{}
	for _, cert := range svidChain {
		data.Write(cert.Raw)
	}
	return diskutil.AtomicWriteFile(l.agentSVIDPath(), data.Bytes(), 0600)
}

func (l legacyDir) DeleteSVID() error {
	return os.Remove(l.agentSVIDPath())
}

func (l legacyDir) bundlePath() string {
	return path.Join(l.dir, "bundle.der")
}

func (l legacyDir) agentSVIDPath() string {
	return path.Join(l.dir, "agent_svid.der")
}
