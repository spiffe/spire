package x509util

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"

	"github.com/spiffe/spire/pkg/common/cryptoutil"
)

func CreateCertificate(template, parent *x509.Certificate, pub, priv any) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func CertificateMatchesPublicKey(certificate *x509.Certificate, publicKey crypto.PublicKey) (bool, error) {
	return cryptoutil.PublicKeyEqual(certificate.PublicKey, publicKey)
}

func CertificateMatchesPrivateKey(certificate *x509.Certificate, privateKey crypto.PrivateKey) (bool, error) {
	return cryptoutil.KeyMatches(privateKey, certificate.PublicKey)
}

func DedupeCertificates(bundles ...[]*x509.Certificate) []*x509.Certificate {
	certs := []*x509.Certificate{}

	// Retain ordering for easier testing
	seenMap := map[string]struct{}{}
	for _, bundle := range bundles {
		for _, cert := range bundle {
			if _, ok := seenMap[string(cert.Raw)]; !ok {
				seenMap[string(cert.Raw)] = struct{}{}
				certs = append(certs, cert)
			}
		}
	}

	return certs
}

func DERFromCertificates(certs []*x509.Certificate) (derBytes []byte) {
	for _, cert := range certs {
		derBytes = append(derBytes, cert.Raw...)
	}
	return derBytes
}

// RawCertsToCertificates parses certificates from the given slice of ASN.1 DER data
func RawCertsToCertificates(rawCerts [][]byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// RawCertsFromCertificates parses ASN.1 DER data from given slice of X.509 Certificates
func RawCertsFromCertificates(certs []*x509.Certificate) [][]byte {
	if certs == nil {
		return nil
	}
	rawCerts := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw)
	}
	return rawCerts
}
