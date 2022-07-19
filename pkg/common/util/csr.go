package util

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
)

func MakeCSR(privateKey interface{}, spiffeID spiffeid.ID) ([]byte, error) {
	return makeCSR(privateKey, &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRE"},
		},
		URIs: []*url.URL{spiffeID.URL()},
	})
}

func MakeCSRWithoutURISAN(privateKey interface{}) ([]byte, error) {
	return makeCSR(privateKey, &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRE"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	})
}

func makeCSR(privateKey interface{}, template *x509.CertificateRequest) ([]byte, error) {
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return csr, nil
}
