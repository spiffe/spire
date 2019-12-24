package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/x509util"
)

func CreateServerCATemplate(spiffeID string, publicKey crypto.PublicKey, trustDomain string, notBefore, notAfter time.Time, serialNumber *big.Int, subject pkix.Name) (*x509.Certificate, error) {
	uri, err := idutil.ParseSpiffeID(spiffeID, idutil.AllowTrustDomain(trustDomain))
	if err != nil {
		return nil, err
	}

	keyID, err := x509util.GetSubjectKeyID(publicKey)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		URIs:         []*url.URL{uri},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SubjectKeyId: keyID,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             publicKey,
	}, nil
}

func CreateX509SVIDTemplate(spiffeID string, publicKey crypto.PublicKey, trustDomain string, notBefore, notAfter time.Time, serialNumber *big.Int) (*x509.Certificate, error) {
	uri, err := idutil.ParseSpiffeID(spiffeID, idutil.AllowAnyInTrustDomain(trustDomain))
	if err != nil {
		return nil, err
	}

	subject := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIRE"},
	}

	keyID, err := x509util.GetSubjectKeyID(publicKey)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		URIs:         []*url.URL{uri},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SubjectKeyId: keyID,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		PublicKey:             publicKey,
	}, nil
}
