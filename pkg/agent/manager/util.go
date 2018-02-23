package manager

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/uri"
)

func getSpiffeIDFromSVID(svid *x509.Certificate) (string, error) {
	URIs, err := uri.GetURINamesFromCertificate(svid)
	if err != nil {
		return "", err
	}
	return URIs[0], nil
}
