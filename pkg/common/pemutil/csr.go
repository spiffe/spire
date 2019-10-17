package pemutil

import (
	"crypto/x509"
	"fmt"
)

func ParseCertificateRequest(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, err := parseBlock(pemBytes, certificateRequestType)
	if err != nil {
		return nil, err
	}
	return csrFromObject(block.Object)
}

func LoadCertificateRequest(path string) (*x509.CertificateRequest, error) {
	block, err := loadBlock(path, certificateRequestType)
	if err != nil {
		return nil, err
	}
	return csrFromObject(block.Object)
}

func csrFromObject(object interface{}) (*x509.CertificateRequest, error) {
	csr, ok := object.(*x509.CertificateRequest)
	if !ok {
		return nil, fmt.Errorf("expected %T; got %T", csr, object)
	}
	return csr, nil
}
