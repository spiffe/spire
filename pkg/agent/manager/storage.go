package manager

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
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
	return ioutil.WriteFile(bundleCachePath, data.Bytes(), 0600)
}

// ReadSVID returns the SVID located at svidCachePath. Returns nil
// if there was some reason by which the SVID couldn't be loaded along
// with the error reason.
func ReadSVID(svidCachePath string) (*x509.Certificate, error) {
	if _, err := os.Stat(svidCachePath); os.IsNotExist(err) {
		return nil, ErrNotCached
	}

	data, err := ioutil.ReadFile(svidCachePath)
	if err != nil {
		return nil, fmt.Errorf("error reading SVID at %s: %s", svidCachePath, err)
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing SVID at %s: %s", svidCachePath, err)
	}
	return cert, nil
}

// StoreSVID writes the specified svid to disk into svidCachePath. Returns nil if all went
// fine, otherwise ir returns an error.
func StoreSVID(svidCachePath string, svid *x509.Certificate) error {
	return ioutil.WriteFile(svidCachePath, svid.Raw, 0600)
}
