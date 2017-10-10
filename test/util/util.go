package util

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path"
	"runtime"
)

var (
	svidPath    = path.Join(ProjectRoot(), "test/fixture/certs/svid.pem")
	svidKeyPath = path.Join(ProjectRoot(), "test/fixture/certs/svid_key.pem")
	caPath      = path.Join(ProjectRoot(), "test/fixture/certs/ca.pem")
	caKeyPath   = path.Join(ProjectRoot(), "test/fixture/certs/ca_key.pem")
)

// LoadCAFixture reads, parses, and returns the pre-defined CA fixture and key
func LoadCAFixture() (ca *x509.Certificate, key *ecdsa.PrivateKey, err error) {
	return LoadCertAndKey(caPath, caKeyPath)
}

// LoadCAFixture reads, parses, and returns the pre-defined SVID fixture and key
func LoadSVIDFixture() (svid *x509.Certificate, key *ecdsa.PrivateKey, err error) {
	return LoadCertAndKey(svidPath, svidKeyPath)
}

// LoadCertAndKey reads and parses both a certificate and a private key at once
func LoadCertAndKey(crtPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	crt, err := LoadCert(crtPath)
	if err != nil {
		return crt, nil, err
	}

	key, err := LoadKey(keyPath)
	return crt, key, err
}

// LoadCert reads and parses an X.509 certificate at the specified path
func LoadCert(path string) (*x509.Certificate, error) {
	block, err := LoadPEM(path)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return crt, nil
}

// LoadKey reads and parses the ECDSA private key at the specified path
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	block, err := LoadPEM(path)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// LoadPEM reads and parses the PEM structure at the specified path
func LoadPEM(path string) (*pem.Block, error) {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	blk, rest := pem.Decode(dat)
	if len(rest) > 0 {
		return nil, fmt.Errorf("error decoding certificate at %s", path)
	}

	return blk, nil
}

// ProjectRoot returns the absolute path to the SPIRE project root
func ProjectRoot() string {
	_, p, _, _ := runtime.Caller(0)
	return path.Join(p, "../../../")
}
