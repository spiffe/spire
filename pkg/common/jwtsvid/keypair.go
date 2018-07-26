package jwtsvid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"
)

var (
	extKeyUsage pkix.Extension
)

func init() {
	// create an empty ASN.1 sequence. this shouldn't fail.
	emptySequence, err := asn1.Marshal([]interface{}{})
	if err != nil {
		panic(err)
	}
	// TODO: add the custom SPIFFE JWT-A-SVID ExtKeyUsage OID when available
	extKeyUsage = pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
		Critical: true,
		Value:    emptySequence,
	}
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func CreateCertificateTemplate(parentCert *x509.Certificate) *x509.Certificate {
	return &x509.Certificate{
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		BasicConstraintsValid: true,
		IsCA:      false,
		NotBefore: parentCert.NotBefore,
		NotAfter:  parentCert.NotAfter,
		URIs:      parentCert.URIs,
		ExtraExtensions: []pkix.Extension{
			extKeyUsage,
		},
	}
}

func ValidateSigningCertificate(cert *x509.Certificate) error {
	if cert.IsCA {
		return errors.New("signing certificate cannot be a CA")
	}
	if time.Now().After(cert.NotAfter) {
		return errors.New("signing certificate is expired")
	}
	if cert.KeyUsage != 0 {
		return errors.New("signing certificate cannot have any key usage")
	}

	// TODO: validate that the signing certificate has the special ExtKeyUsage OID

	return nil
}
