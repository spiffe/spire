package manager

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func getSpiffeIDFromSVID(svid *x509.Certificate) (string, error) {
	id, err := x509svid.IDFromCert(svid)
	if err != nil {
		return "", err
	}

	return id.String(), nil
}
