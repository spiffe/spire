package pemutil

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func ParseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, err := parseBlock(pemBytes, certificateType)
	if err != nil {
		return nil, err
	}
	return certFromObject(block.Object)
}

func LoadCertificate(path string) (*x509.Certificate, error) {
	block, err := loadBlock(path, certificateType)
	if err != nil {
		return nil, err
	}
	return certFromObject(block.Object)
}

func ParseCertificates(pemBytes []byte) (certs []*x509.Certificate, err error) {
	blocks, err := parseBlocks(pemBytes, 0, certificateType)
	if err != nil {
		return nil, err
	}
	return certsFromBlocks(blocks)
}

func LoadCertificates(path string) (certs []*x509.Certificate, err error) {
	blocks, err := loadBlocks(path, 0, certificateType)
	if err != nil {
		return nil, err
	}
	return certsFromBlocks(blocks)
}

func EncodeCertificates(certs []*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, cert := range certs {
		encodeCertificate(&buf, cert)
	}
	return buf.Bytes()
}

func SaveCertificates(path string, certs []*x509.Certificate, mode os.FileMode) error {
	return ioutil.WriteFile(path, EncodeCertificates(certs), mode)
}

func EncodeCertificate(cert *x509.Certificate) []byte {
	var buf bytes.Buffer
	encodeCertificate(&buf, cert)
	return buf.Bytes()
}

func SaveCertificate(path string, cert *x509.Certificate, mode os.FileMode) error {
	return ioutil.WriteFile(path, EncodeCertificate(cert), mode)
}

func certFromObject(object interface{}) (*x509.Certificate, error) {
	cert, ok := object.(*x509.Certificate)
	if !ok {
		return nil, fmt.Errorf("expected %T; got %T", cert, object)
	}
	return cert, nil
}

func certsFromBlocks(blocks []Block) (certs []*x509.Certificate, err error) {
	for _, block := range blocks {
		cert, err := certFromObject(block.Object)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func encodeCertificate(w io.Writer, cert *x509.Certificate) {
	pem.Encode(w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}
