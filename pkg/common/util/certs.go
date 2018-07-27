package util

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// NewCertPool creates a new *x509.CertPool based on the certificates given
// as parameters.
func NewCertPool(certs ...*x509.Certificate) *x509.CertPool {
	certPool := x509.NewCertPool()
	for _, cert := range certs {
		certPool.AddCert(cert)
	}
	return certPool
}

// LoadCertPool loads one or more certificates into an *x509.CertPool from
// a PEM file on disk.
func LoadCertPool(path string) (*x509.CertPool, error) {
	certs, err := LoadCertificates(path)
	if err != nil {
		return nil, err
	}
	return NewCertPool(certs...), nil
}

// LoadCertificates loads one or more certificates into an []*x509.Certificate from
// a PEM file on disk.
func LoadCertificates(path string) ([]*x509.Certificate, error) {
	rest, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for blockno := 0; ; blockno++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate in block %d: %v", blockno, err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found in file")
	}

	return certs, nil
}
