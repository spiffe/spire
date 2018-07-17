package pemutil

import (
	"crypto/x509"
	"fmt"
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

func certFromObject(object interface{}) (*x509.Certificate, error) {
	cert, ok := object.(*x509.Certificate)
	if !ok {
		return nil, fmt.Errorf("expected %T; got %T", cert, object)
	}
	return cert, nil
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
