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
	data, mtime, err := readFile(legacyBundlePath(dir))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to read legacy bundle: %w", err)
	}

	bundle, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to parse legacy bundle: %w", err)
	}
	return bundle, mtime, nil
}

func storeLegacyBundle(dir string, bundle []*x509.Certificate) error {
	data := new(bytes.Buffer)
	for _, cert := range bundle {
		data.Write(cert.Raw)
	}
	if err := diskutil.AtomicWritePrivateFile(legacyBundlePath(dir), data.Bytes()); err != nil {
		return fmt.Errorf("failed to store legacy bundle: %w", err)
	}
	return nil
}

func loadLegacySVID(dir string) ([]*x509.Certificate, time.Time, error) {
	data, mtime, err := readFile(legacySVIDPath(dir))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to read legacy SVID: %w", err)
	}

	certChain, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to parse legacy SVID: %w", err)
	}
	return certChain, mtime, nil
}

func storeLegacySVID(dir string, svidChain []*x509.Certificate) error {
	data := new(bytes.Buffer)
	for _, cert := range svidChain {
		data.Write(cert.Raw)
	}
	if err := diskutil.AtomicWritePrivateFile(legacySVIDPath(dir), data.Bytes()); err != nil {
		return fmt.Errorf("failed to store legacy SVID: %w", err)
	}
	return nil
}

func deleteLegacySVID(dir string) error {
	err := os.Remove(legacySVIDPath(dir))
	switch {
	case err == nil, errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("failed to delete legacy SVID: %w", err)
	}
}

func legacyBundlePath(dir string) string {
	return filepath.Join(dir, "bundle.der")
}

func legacySVIDPath(dir string) string {
	return filepath.Join(dir, "agent_svid.der")
}
