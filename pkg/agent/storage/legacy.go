package storage

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/spire/pkg/common/diskutil"
)

func loadLegacyBundle(dir string) ([]*x509.Certificate, time.Time, error) {
	path := legacyBundlePath(dir)
	data, mtime, err := readFile(path)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("error reading bundle at %s: %w", path, err)
	}

	bundle, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("error parsing bundle at %s: %w", path, err)
	}
	return bundle, mtime, nil
}

func storeLegacyBundle(dir string, bundle []*x509.Certificate) error {
	data := new(bytes.Buffer)
	for _, cert := range bundle {
		data.Write(cert.Raw)
	}
	return diskutil.AtomicWriteFile(legacyBundlePath(dir), data.Bytes(), 0600)
}

func loadLegacySVID(dir string) ([]*x509.Certificate, time.Time, error) {
	path := legacySVIDPath(dir)
	data, mtime, err := readFile(path)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("error reading SVID at %s: %w", path, err)
	}

	certChain, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("error parsing SVID at %s: %w", path, err)
	}
	return certChain, mtime, nil
}

func storeLegacySVID(dir string, svidChain []*x509.Certificate) error {
	data := new(bytes.Buffer)
	for _, cert := range svidChain {
		data.Write(cert.Raw)
	}
	return diskutil.AtomicWriteFile(legacySVIDPath(dir), data.Bytes(), 0600)
}

func deleteLegacySVID(dir string) error {
	err := os.Remove(legacySVIDPath(dir))
	switch {
	case err == nil, errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		return err
	}
}

func legacyBundlePath(dir string) string {
	return filepath.Join(dir, "bundle.der")
}

func legacySVIDPath(dir string) string {
	return filepath.Join(dir, "agent_svid.der")
}
