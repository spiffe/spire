package util

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"

	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/zeebo/errs"
)

func MakeCSR(privateKey interface{}, spiffeId string) (csr []byte, err error) {
	uriSAN, err := idutil.ParseSpiffeID(spiffeId, idutil.AllowAny())
	if err != nil {
		return nil, err
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRE"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		URIs:               []*url.URL{uriSAN},
	}

	csr, err = x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return csr, nil
}
