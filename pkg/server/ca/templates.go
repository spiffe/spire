package ca

import (
	"crypto/x509"
	"math/big"
	"time"

	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
)

func CreateServerCATemplate(csrDER []byte, trustDomain string, notBefore, notAfter time.Time, serialNumber *big.Int) (*x509.Certificate, error) {
	csr, err := x509svid.ParseAndValidateCSR(csrDER, idutil.AllowTrustDomain(trustDomain))
	if err != nil {
		return nil, err
	}

	keyID, err := x509util.GetSubjectKeyId(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		URIs:         csr.URIs,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SubjectKeyId: keyID,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:      true,
		PublicKey: csr.PublicKey,
	}, nil
}

func CreateX509SVIDTemplate(csrDER []byte, trustDomain string, notBefore, notAfter time.Time, serialNumber *big.Int) (*x509.Certificate, error) {
	csr, err := x509svid.ParseAndValidateCSR(csrDER, idutil.AllowAnyInTrustDomain(trustDomain))
	if err != nil {
		return nil, err
	}

	keyID, err := x509util.GetSubjectKeyId(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		URIs:         csr.URIs,
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
		PublicKey:             csr.PublicKey,
	}, nil
}
