package x509util

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"

	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
)

func CertificateMatchesPublicKey(certificate *x509.Certificate, publicKey crypto.PublicKey) (bool, error) {
	return cryptoutil.PublicKeyEqual(certificate.PublicKey, publicKey)
}

func CertificateMatchesPrivateKey(certificate *x509.Certificate, privateKey crypto.PrivateKey) (bool, error) {
	return cryptoutil.KeyMatches(privateKey, certificate.PublicKey)
}

func CreateCertificate(ctx context.Context, km keymanager.KeyManager, template, parent *x509.Certificate, parentKeyID string, publicKey crypto.PublicKey) (*x509.Certificate, error) {
	parentPublicKey := parent.PublicKey
	if parentPublicKey == nil {
		// Pull the public key from the key manager. In the self-signing case, the
		// parent certificate PublicKey field is not likely to be set.
		var err error
		parentPublicKey, err = cryptoutil.GetPublicKey(ctx, km, parentKeyID)
		if err != nil {
			return nil, err
		}
	}

	signer := cryptoutil.NewKeyManagerSigner(km, parentKeyID, parentPublicKey)
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
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
	rawCerts := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw)
	}
	return rawCerts
}
