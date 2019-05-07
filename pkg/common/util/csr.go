package util

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"

	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/zeebo/errs"
)

func MakeCSR(privateKey interface{}, spiffeID string) ([]byte, error) {
	var uris []*url.URL
	if spiffeID != "" {
		uri, err := idutil.ParseSpiffeID(spiffeID, idutil.AllowAny())
		if err != nil {
			return nil, err
		}
		uris = append(uris, uri)
	}
	return makeCSR(privateKey, &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRE"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               uris,
	})
}

func makeCSR(privateKey interface{}, template *x509.CertificateRequest) ([]byte, error) {
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return csr, nil
}
