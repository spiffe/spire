package manager

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spiffe/spire/pkg/common/diskutil"
)

// ReadBundle returns the bundle located at bundleCachePath. Returns nil
// if there was some reason by which the bundle couldn't be loaded along with
// the error reason.
func ReadBundle(bundleCachePath string) ([]*x509.Certificate, error) {
	if _, err := os.Stat(bundleCachePath); os.IsNotExist(err) {
		return nil, ErrNotCached
	}

	data, err := ioutil.ReadFile(bundleCachePath)
	if err != nil {
		return nil, fmt.Errorf("error reading bundle at %s: %s", bundleCachePath, err)
	}

	bundle, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing bundle at %s: %s", bundleCachePath, err)
	}
	return bundle, nil
}

// StoreBundle writes the bundle to disk into bundleCachePath. Returns nil if all went
// fine, otherwise ir returns an error.
func StoreBundle(bundleCachePath string, bundle []*x509.Certificate) error {
	// Write all certs to data bytes buffer.
	data := &bytes.Buffer{}
	for _, cert := range bundle {
		data.Write(cert.Raw)
	}

	// Write data to disk.
	return diskutil.AtomicWriteFile(bundleCachePath, data.Bytes(), 0600)
}

// ReadSVID returns the SVID located at svidCachePath. Returns nil
// if there was some reason by which the SVID couldn't be loaded along
// with the error reason.
func ReadSVID(svidCachePath string) ([]*x509.Certificate, error) {
	data, err := ioutil.ReadFile(svidCachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotCached
		}
		return nil, fmt.Errorf("error reading SVID at %s: %s", svidCachePath, err)
	}

	certChain, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing SVID at %s: %s", svidCachePath, err)
	}
	return certChain, nil
}

// StoreSVID writes the specified svid to disk into svidCachePath. Returns nil if all went
// fine, otherwise it returns an error.
func StoreSVID(svidCachePath string, svidChain []*x509.Certificate) error {
	data := &bytes.Buffer{}
	for _, cert := range svidChain {
		data.Write(cert.Raw)
	}
	return diskutil.AtomicWriteFile(svidCachePath, data.Bytes(), 0600)
}
