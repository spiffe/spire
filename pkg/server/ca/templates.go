package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
)

func CreateServerCATemplate(spiffeID spiffeid.ID, publicKey crypto.PublicKey, trustDomain spiffeid.TrustDomain, notBefore, notAfter time.Time, serialNumber *big.Int, subject pkix.Name) (*x509.Certificate, error) {
	if err := verifySameTrustDomain(trustDomain, spiffeID); err != nil {
		return nil, err
	}

	keyID, err := x509util.GetSubjectKeyID(publicKey)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		URIs:         []*url.URL{spiffeID.URL()},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SubjectKeyId: keyID,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             publicKey,
	}, nil
}

func CreateX509SVIDTemplate(spiffeID spiffeid.ID, publicKey crypto.PublicKey, trustDomain spiffeid.TrustDomain, notBefore, notAfter time.Time, serialNumber *big.Int) (*x509.Certificate, error) {
	if err := api.VerifyTrustDomainMemberID(trustDomain, spiffeID); err != nil {
		return nil, err
	}

	keyID, err := x509util.GetSubjectKeyID(publicKey)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		URIs:         []*url.URL{spiffeID.URL()},
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

func verifySameTrustDomain(td spiffeid.TrustDomain, id spiffeid.ID) error {
	if !id.MemberOf(td) {
		return fmt.Errorf("%q is not a member of trust domain %q", id, td)
	}
	return nil
}
