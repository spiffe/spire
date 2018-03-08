package manager

import (
	"crypto/x509"
	"errors"

	"github.com/spiffe/go-spiffe/uri"
)

func getSpiffeIDFromSVID(svid *x509.Certificate) (string, error) {
	URIs, err := uri.GetURINamesFromCertificate(svid)
	if err != nil {
		return "", err
	}

	if len(URIs) == 0 {
		return "", errors.New("certificate does not have a spiffeId")
	}

	return URIs[0], nil
}
