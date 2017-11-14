package util

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/spiffe/go-spiffe/uri"
)

func MakeCSR(privateKey interface{}, spiffeId string) (csr []byte, err error) {

	uriSANs, err := uri.MarshalUriSANs([]string{spiffeId})
	if err != nil {
		return csr, err
	}

	uriSANExtension := []pkix.Extension{{
		Id:       uri.OidExtensionSubjectAltName,
		Value:    uriSANs,
		Critical: true,
	}}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRE"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions:    uriSANExtension,
	}

	csr, err = x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return csr, err
	}
	return
}
